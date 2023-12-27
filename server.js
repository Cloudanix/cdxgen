import connect from "connect";
import http from "node:http";
import bodyParser from "body-parser";
import url from "node:url";
import { spawnSync } from "node:child_process";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { createBom, submitBom } from "./index.js";
import { postProcess } from "./postgen.js";
import { Octokit } from "@octokit/core";
import tar from "tar-fs";
import zlib from "zlib";

import compression from "compression";

// Timeout milliseconds. Default 10 mins
const TIMEOUT_MS =
  parseInt(process.env.CDXGEN_SERVER_TIMEOUT_MS) || 10 * 60 * 1000;

const app = connect();

app.use(
  bodyParser.json({
    deflate: true,
    limit: "1mb"
  })
);
app.use(compression());

const gitClone = (repoUrl, branch = null) => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), path.basename(repoUrl))
  );

  if (branch == null) {
    console.log("Cloning Repo", "to", tempDir);
    const result = spawnSync(
      "git",
      ["clone", repoUrl, "--depth", "1", tempDir],
      {
        encoding: "utf-8",
        shell: false
      }
    );
    if (result.status !== 0 || result.error) {
      console.log(result.error);
    }
  } else {
    console.log("Cloning repo with optional branch", "to", tempDir);
    const result = spawnSync(
      "git",
      ["clone", repoUrl, "--branch", branch, "--depth", "1", tempDir],
      {
        encoding: "utf-8",
        shell: false
      }
    );
    if (result.status !== 0 || result.error) {
      console.log(result.error);
    }
  }

  return tempDir;
};
async function gitTar(repository, owner, token, branch = null){
  if(branch == null)
  {
    branch = "main"
  }
  const target = fs.mkdtempSync(
    path.join(os.tmpdir(), path.basename(repoUrl))
  );
  console.log("Downloading Repo", "in", target);
  const octokit = new Octokit({
    auth: token,
  })
  const response = await octokit.request('GET /repos/{owner}/{repo}/tarball/{ref}', {
    owner: owner,
    repo: repository,
    ref: branch,
    headers: {
      'X-GitHub-Api-Version': '2022-11-28'
    }
  })
  if(response.status == 200 || response.status == 302){
    var tarballData = response.data;
    var tarFile = target + owner + repository + ".tar";
    var decompressedData = zlib.gunzipSync(tarballData);
    fs.writeFileSync(tarFile, decompressedData);

    var extractionStream = tar.extract(target);
    extractionStream.on('finish', () => {
      // Extraction is complete, now delete the tarFile
      fs.unlinkSync(tarFile);
      console.log(`Extraction complete`);
    });
    // extracting a directory
    fs.createReadStream(tarFile).pipe(extractionStream);
  }
  else{
    console.log("Error downloading repo: " + response.status);
  }
  return target;
};

const parseQueryString = (q, body, options = {}) => {
  if (body && Object.keys(body).length) {
    options = Object.assign(options, body);
  }

  const queryParams = [
    "type",
    "multiProject",
    "requiredOnly",
    "noBabel",
    "installDeps",
    "projectId",
    "projectName",
    "projectGroup",
    "projectVersion",
    "parentUUID",
    "serverUrl",
    "apiKey",
    "specVersion",
    "filter",
    "only",
    "autoCompositions",
    "git",
    "gitBranch",
    "active",
    "private",
    "owner",
    "repository",
    "token"
  ];

  for (const param of queryParams) {
    if (q[param]) {
      options[param] = q[param];
    }
  }

  options.projectType = options.type;
  delete options.type;

  return options;
};

const configureServer = (cdxgenServer) => {
  cdxgenServer.headersTimeout = TIMEOUT_MS;
  cdxgenServer.requestTimeout = TIMEOUT_MS;
  cdxgenServer.timeout = 0;
  cdxgenServer.keepAliveTimeout = 0;
};

const start = (options) => {
  console.log("Listening on", options.serverHost, options.serverPort);
  const cdxgenServer = http
    .createServer(app)
    .listen(options.serverPort, options.serverHost);
  configureServer(cdxgenServer);

  app.use("/health", async function (_req, res) {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ status: "OK" }, null, 2));
  });

  app.use("/sbom", async function (req, res) {
    const q = url.parse(req.url, true).query;
    let cleanup = false;
    const reqOptions = parseQueryString(
      q,
      req.body,
      Object.assign({}, options)
    );
    const filePath = q.path || q.url || req.body.path || req.body.url;
    let srcDir = filePath;
    if(reqOptions.git == true)
    {
      if(reqOptions.private == true)
      {
        srcDir = gitTar(reqOptions.repository, reqOptions.owner, reqOptions.token, reqOptions.gitBranch);
      }
      else if (!filePath) {
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(
          "{'error': 'true', 'message': 'path or url is required.'}\n"
        );
      }
      else if (filePath.startsWith("http") || filePath.startsWith("git")) {
        srcDir = gitClone(filePath, reqOptions.gitBranch);
      }
      cleanup = true;
  }
    if (!filePath) {
      res.writeHead(500, { "Content-Type": "application/json" });
      return res.end(
        "{'error': 'true', 'message': 'path or url is required.'}\n"
      );
    }
    res.writeHead(200, { "Content-Type": "application/json" });

    console.log("Generating SBOM for", srcDir);
    let bomNSData = (await createBom(srcDir, reqOptions)) || {};
    if (reqOptions.requiredOnly || reqOptions["filter"] || reqOptions["only"]) {
      bomNSData = postProcess(bomNSData, reqOptions);
    }
    if (bomNSData.bomJson) {
      if (
        typeof bomNSData.bomJson === "string" ||
        bomNSData.bomJson instanceof String
      ) {
        res.write(bomNSData.bomJson);
      } else {
        res.write(JSON.stringify(bomNSData.bomJson, null, 2));
      }
    }
    if (reqOptions.serverUrl && reqOptions.apiKey) {
      console.log("Publishing SBOM to Dependency Track");
      submitBom(reqOptions, bomNSData.bomJson);
    }
    res.end("\n");
    if (cleanup && srcDir && srcDir.startsWith(os.tmpdir()) && fs.rmSync) {
      console.log(`Cleaning up ${srcDir}`);
      fs.rmSync(srcDir, { recursive: true, force: true });
    }
  });
};
export { configureServer, start };