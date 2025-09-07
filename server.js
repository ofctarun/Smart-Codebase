require("dotenv").config();
const express = require("express");
const axios = require("axios");
const path = require("path");
const session = require("express-session");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const port = 3000;

// Session Configuration
app.use(
  session({
    secret: "my-super-strong-secret-key-that-is-long",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true if using HTTPS in production
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Middleware to protect routes
const isAuthenticated = (req, res, next) => {
  if (req.session.accessToken) {
    return next();
  }
  // If the request is for an API route, always return JSON
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(401).json({ error: "User not authenticated. Please log in again." });
  }
  // Otherwise, redirect for normal page requests
  res.redirect("/index.html");
};

app.use(express.json());

// --- CORE ROUTES ---
app.get("/", (req, res) => {
  if (req.session.accessToken) {
    res.redirect("/dashboard.html");
  } else {
    res.redirect("/index.html");
  }
});
app.get("/index.html", (req, res) =>
  res.sendFile(path.join(__dirname, "index.html"))
);
app.get("/home.html", isAuthenticated, (req, res) =>
  res.sendFile(path.join(__dirname, "home.html"))
);

app.get("/callback", (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect("/index.html?error=auth_failed");

  const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
  const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

  console.log("Received OAuth code:", code);
  console.log(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET);

  axios
    .post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code: code,
      },
      { headers: { Accept: "application/json" } }
    )
    .then((tokenResponse) => {
      const accessToken = tokenResponse.data.access_token;
      console.log("Access Token:", accessToken);
      if (accessToken) {
        req.session.accessToken = accessToken;
        res.redirect("/dashboard.html");
      } else {
        res.redirect("/index.html?error=token_failed");
      }
    })
    .catch((err) => {
      console.error("Error in OAuth token exchange:", err.message);
      res.redirect("/index.html?error=internal_error");
    });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Could not log out." });
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Logged out successfully." });
  });
});

// --- PROTECTED PAGE ROUTES ---
app.use("/dashboard.html", isAuthenticated);
app.use("/repo.html", isAuthenticated);

app.use(express.static(__dirname));

// --- API ---
const apiRouter = express.Router();
apiRouter.use(isAuthenticated);

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

// Get initial user and repo data
apiRouter.get("/user-data", async (req, res) => {
  try {
    const token = req.session.accessToken;
    const [userResponse, reposResponse] = await Promise.all([
      axios.get("https://api.github.com/user", {
        headers: { Authorization: `token ${token}` },
      }),
      axios.get("https://api.github.com/user/repos", {
        headers: { Authorization: `token ${token}` },
        params: { sort: "updated", per_page: 100 },
      }),
    ]);
    req.session.userReposCache = reposResponse.data;
    res.json({ userData: userResponse.data, reposData: reposResponse.data });
  } catch (error) {
    console.error("Error fetching user data:", error.message);
    req.session.destroy();
    res.status(401).json({ error: "Authentication failed." });
  }
});

// NEW: Get detailed contribution data using GraphQL API
apiRouter.get("/contribution-data", async (req, res) => {
  const token = req.session.accessToken;
  const userResponse = await axios.get("https://api.github.com/user", {
    headers: { Authorization: `token ${token}` },
  });
  const username = userResponse.data.login;

  const graphqlQuery = {
    query: `
            query($userName: String!) {
              user(login: $userName) {
                contributionsCollection {
                  contributionCalendar {
                    totalContributions
                    months {
                        name
                        totalWeeks
                    }
                    weeks {
                      contributionDays {
                        contributionCount
                        date
                        weekday
                        color
                      }
                    }
                  }
                }
              }
            }
        `,
    variables: {
      userName: username,
    },
  };

  try {
    const response = await axios.post(
      "https://api.github.com/graphql",
      graphqlQuery,
      {
        headers: {
          Authorization: `bearer ${token}`, // GraphQL uses 'bearer'
        },
      }
    );
    res.json(
      response.data.data.user.contributionsCollection.contributionCalendar
    );
  } catch (error) {
    console.error("Error fetching contribution data:", error.message);
    res.status(500).json({ error: "Failed to fetch contribution data." });
  }
});

// Get contents of a specific directory
apiRouter.get("/repo-contents", async (req, res) => {
  const { owner, repo, path = "" } = req.query;
  const token = req.session.accessToken;
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
    const response = await axios.get(url, {
      headers: { Authorization: `token ${token}` },
    });
    response.data.sort(
      (a, b) =>
        (a.type === "dir" ? -1 : 1) - (b.type === "dir" ? -1 : 1) ||
        a.name.localeCompare(b.name)
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch repository contents." });
  }
});

// Get the full file tree of a repo
apiRouter.get("/repo-tree", async (req, res) => {
  const { owner, repo } = req.query;
  const token = req.session.accessToken;
  try {
    const repoUrl = `https://api.github.com/repos/${owner}/${repo}`;
    const repoResponse = await axios.get(repoUrl, {
      headers: { Authorization: `token ${token}` },
    });
    const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${repoResponse.data.default_branch}?recursive=1`;
    const treeResponse = await axios.get(treeUrl, {
      headers: { Authorization: `token ${token}` },
    });
    res.json({ tree: treeResponse.data.tree });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch repository tree." });
  }
});

// Get a single file's content and SHA
apiRouter.get("/file-content", async (req, res) => {
  const { owner, repo, path } = req.query;
  const token = req.session.accessToken;
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github.v3+json",
      },
    });
    const isImage = /\.(jpg|jpeg|png|gif|svg|webp)$/i.test(path);
    const fileContent = isImage
      ? response.data.content
      : Buffer.from(response.data.content, "base64").toString("utf8");
    res.json({ content: fileContent, sha: response.data.sha });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch file content." });
  }
});

// Commit file changes
apiRouter.post("/commit-file", async (req, res) => {
  const { owner, repo, path, message, content, sha } = req.body;
  const token = req.session.accessToken;
  if (!owner || !repo || !path || !message || content === undefined || !sha) {
    return res.status(400).json({ error: "Missing required commit data." });
  }
  try {
    const commitUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
    const commitData = {
      message,
      content: Buffer.from(content).toString("base64"),
      sha,
    };
    const commitResponse = await axios.put(commitUrl, commitData, {
      headers: {
        Authorization: `token ${token}`,
        Accept: "application/vnd.github.v3+json",
      },
    });
    res.json({ success: true, data: commitResponse.data });
  } catch (error) {
    res.status(500).json({ error: "Failed to commit file." });
  }
});

// AI search
apiRouter.post("/ai-search", async (req, res) => {
  const { query } = req.body;
  const allRepos = req.session.userReposCache || [];
  
  if (!query || allRepos.length === 0) {
    return res.status(400).json({ error: "Missing query or repos." });
  }

  try {
    // Check if user specified a particular repository in the query
    const repoNameMatch = query.match(/in\s+(?:repo|repository)\s+["']?([^"'\s]+)["']?/i);
    const specificRepo = repoNameMatch ? repoNameMatch[1] : null;

    let reposToSearch = allRepos;
    if (specificRepo) {
      // If specific repo mentioned, search only in that repo
      const matchedRepo = allRepos.find(r => 
        r.name.toLowerCase().includes(specificRepo.toLowerCase()) ||
        specificRepo.toLowerCase().includes(r.name.toLowerCase())
      );
      reposToSearch = matchedRepo ? [matchedRepo] : [];
    }

    if (reposToSearch.length === 0) {
      return res.json({ results: [] });
    }

    // Use AI to identify relevant repositories and files
    const reposForPrompt = reposToSearch.map((r) => ({
      name: r.name,
      description: r.description || "",
    }));

    // First, get file trees for all relevant repositories
    const repoTreePromises = reposToSearch.map(async (repo) => {
      try {
        const treeUrl = `https://api.github.com/repos/${repo.owner.login}/${repo.name}/git/trees/${repo.default_branch}?recursive=1`;
        const treeResponse = await axios.get(treeUrl, {
          headers: { Authorization: `token ${req.session.accessToken}` },
        });
        return {
          repo,
          tree: treeResponse.data.tree,
          filePaths: treeResponse.data.tree.filter(n => n.type === "blob").map(n => n.path)
        };
      } catch (error) {
        console.error(`Error fetching tree for ${repo.name}:`, error.message);
        return { repo, tree: [], filePaths: [] };
      }
    });

    const repoTrees = await Promise.all(repoTreePromises);
    const validRepoTrees = repoTrees.filter(rt => rt.filePaths.length > 0);

    if (validRepoTrees.length === 0) {
      return res.json({ results: [] });
    }

    // Create a comprehensive prompt for AI to search across all repos
    const allFilePaths = validRepoTrees.map(rt => ({
      repoName: rt.repo.name,
      files: rt.filePaths
    }));

    // Detect if the query is a file type search
    const fileTypeMap = {
      'html': ['.html'],
      'javascript': ['.js', '.jsx', '.ts', '.tsx'],
      'css': ['.css'],
      'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico', '.bmp'],
      'json': ['.json'],
      'markdown': ['.md'],
      'python': ['.py'],
      'java': ['.java'],
      'php': ['.php'],
      'ruby': ['.rb'],
      'go': ['.go'],
      'c++': ['.cpp', '.c', '.h'],
      'c': ['.c', '.h'],
      'sql': ['.sql'],
      'xml': ['.xml'],
      'yaml': ['.yml', '.yaml'],
      'bash': ['.sh'],
      'powershell': ['.ps1'],
      'batch': ['.bat']
    };
    let fileTypeKey = null;
    for (const key in fileTypeMap) {
      if (new RegExp(`\\b${key}\\b`, 'i').test(query)) {
        fileTypeKey = key;
        break;
      }
    }
    let fileTypeInstruction = '';
    if (fileTypeKey) {
      fileTypeInstruction = `\nUser is searching for all files of type: ${fileTypeKey.toUpperCase()} (${fileTypeMap[fileTypeKey].join(', ')}).\nReturn ALL files with these extensions across the relevant repositories. If a specific repo is mentioned, only search that repo.`;
    }

    const searchPrompt = `User Query: "${query}"
Available Repositories and their files:
${JSON.stringify(allFilePaths, null, 2)}
${fileTypeInstruction}

Find the most relevant files across ALL repositories. Consider:
1. Direct name matches (e.g., "images" should match image files)
2. Content relevance based on file extensions and paths
3. Repository context and descriptions

Respond with a JSON object containing relevant files from multiple repositories:
{
  "results": [
    {
      "repoName": "repository-name",
      "filePaths": ["path/to/file1.ext", "path/to/file2.ext"]
    }
  ]
}

Prioritize files that directly match the query terms. If searching for a file type, include ALL files of that type across repositories.`;

    const searchResult = await model.generateContent(searchPrompt);
    const aiResponse = JSON.parse(
      searchResult.response
        .text()
        .replace(/```json/g, "")
        .replace(/```/g, "")
        .trim()
    );

    // Build final results
    const finalResults = [];
    
    if (aiResponse.results && Array.isArray(aiResponse.results)) {
      for (const result of aiResponse.results) {
        const repoTree = validRepoTrees.find(rt => rt.repo.name === result.repoName);
        if (repoTree && result.filePaths) {
          for (const filePath of result.filePaths) {
            const fileNode = repoTree.tree.find(n => n.path === filePath);
            if (fileNode) {
              finalResults.push({
                type: "file",
                data: {
                  path: filePath,
                  name: filePath.split("/").pop(),
                  repo: {
                    name: result.repoName,
                    owner: { login: repoTree.repo.owner.login },
                  },
                },
              });
            }
          }
        }
      }
    }

    // If no specific files found but we have relevant repos, return repo results
    if (finalResults.length === 0 && validRepoTrees.length > 0) {
      const repoResults = validRepoTrees.slice(0, 5).map(rt => ({
        type: "repo",
        data: rt.repo
      }));
      return res.json({ results: repoResults });
    }

    res.json({ results: finalResults });
  } catch (error) {
    console.error("AI search error:", error);
    res.status(500).json({ error: "An error occurred during AI search." });
  }
});

app.use("/api", apiRouter);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
