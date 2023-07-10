# PGP, GPG and how to successfully run the release GitHub action.
1. log in / create your TerraformRegistry account.
2. install gpg (preferably using WSL terminal, which may contain gpg already): ```choco install gnupg```
3. generate a (RSA type) gpg key, with NO passphrase: ```gpg --full-generate-key```. The email entered here should not be relevant as long as the public and private key entered into GitHub and TerraformRegistry (below steps) is done correctly.
4. check that you've successfully generated the key, which will show you the ID of the key: ```gpg --list-keys```
5. export the public key: ```gpg --armor --export ID > public.asc```
6. export the private key: ```gpg --armor --export-secret-key ID > private.asc```
7. add GPG key to GitHub account (settings->SSH/GPG keys->New): this is using the public key
8. add GPG key to GitHub repo secrets (repo->settings->Secrets and variables->actions->New Repository secret): key->GPG_PRIVATE_KEY value->private key
9. add GPG key to TerraformRegistry account (settings->New->Select Namespace->Insert public key->Source: GitHub->Source Url: GitHub Repo url)
10. create a new GitHub release: repo->Releases->Draft New Release->create new tag (vx.x.x)->set as latest->publish. this should trigger a new action run
11. ~10 mins later, the GitHub action should have finished. Check your release has been populated with ~18 assets.
12. TerraformRegistry provider->settings->Resync. This should pull your latest release after a couple of mins.
