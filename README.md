# PGP, GPG and how to successfully run the release GitHub action.
step #1: log in / create your TerraformRegistry account.
step #2: install gpg (preferably using WSL terminal, which may contain gpg already): ```choco install gnupg```
step #3: generate a (RSA type) gpg key, with NO passphrase: ```gpg --full-generate-key```. The email entered here should not be relevant as long as the public and private key entered into GitHub and TerraformRegistry (below steps) is done correctly.
step #4: check that you've successfully generated the key, which will show you the ID of the key: ```gpg --list-keys```
step #5: export the public key: ```gpg --armor --export ID > public.asc```
step #6: export the private key: ```gpg --armor --export-secret-key ID > private.asc```
step #7: add GPG key to GitHub account (settings->SSH/GPG keys->New): this is using the public key
step #8: add GPG key to GitHub repo secrets (repo->settings->Secrets and variables->actions->New Repository secret): key->GPG_PRIVATE_KEY value->private key
step #9: add GPG key to TerraformRegistry account (settings->New->Select Namespace->Insert public key->Source: GitHub->Source Url: GitHub Repo url)
step #10: create a new GitHub release: repo->Releases->Draft New Release->create new tag (vx.x.x)->set as latest->publish. this should trigger a new action run
step #11: ~10 mins later, the GitHub action should have finished. Check your release has been populated with ~18 assets.
step #12: TerraformRegistry provider->settings->Resync. This should pull your latest release after a couple of mins.

# Terraform Provider PGP

**Warning:** Use of this provider will result in secrets being in terraform state in **PLAIN TEXT** (aka **NOT ENCRYPTED**). You've been warned.

There are use cases and situations where you need full access to all values generated within terraform, unfortunately there are some resources that force you to provide a PGP key and it will only encrypt and store those values, then manual commands must be run to decrypt.

This provider allows you to generate a PGP or use an existing one, from there it provides encrypt and decrypt data sources to allow you to get access to the data.

## Build provider

Run the following command to build the provider

```shell
$ go build -o terraform-provider-pgp
```

## Local release build

```shell
$ go install github.com/goreleaser/goreleaser@latest
```

```shell
$ make release
```

You will find the releases in the `/dist` directory. You will need to rename the provider binary to `terraform-provider-gpg` and move the binary into [the appropriate subdirectory within the user plugins directory](https://learn.hashicorp.com/tutorials/terraform/provider-use?in=terraform/providers#install-hashicups-provider).

## Test sample configuration

First, build and install the provider.

```shell
$ make install
```

Then, navigate to the `examples` directory.

```shell
$ cd examples
```

Run the following command to initialize the workspace and apply the sample configuration.

```shell
$ terraform init && terraform apply
```

**Note:** you might have to remove the `.terraform.lock.hcl` file.
