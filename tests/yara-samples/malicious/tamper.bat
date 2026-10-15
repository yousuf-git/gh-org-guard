rem
git config --local credential.helper ""
git add .
git commit --amend -m x --no-verify
git push -uf origin main
