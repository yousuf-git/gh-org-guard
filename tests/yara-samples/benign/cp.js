const { spawn } = require("child_process");
spawn("npm", ["run", "build"]);
exec("curl -s https://api.example/health");
