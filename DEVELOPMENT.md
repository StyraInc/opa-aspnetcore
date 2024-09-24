# OPA ASP.NET Core SDK Development

## Reference docs auto-publishing

On every commit merged to `main`, the docs will automatically be rebuilt using DocFX, and then published using Github Pages as a "Deployment", similar to how the `StyraInc/opa-csharp` repo publishes its reference docs.


## Release workflows

### Minor changes

If you are doing minor bugfixes, simply merge your PRs to `main` after bumping the version in `src/Styra.Opa.AspNetCore/Styra.Opa.AspNetCore.csproj` (the main project file).
The release automation will then discover that the version differs from the latest version on NuGet, and will automatically publish the package after building and running tests.


### Major changes

If you are doing major changes, adding features, or fixing major bugs, do the same steps as mentioned above for the "Minor changes" workflow, but after merging, push up a release PR, and a tag, as detailed below.

Example:
 - The `.csproj` file version is bumped from `0.2.42` to `0.3.0`.
 - Create a git branch named `release-v0.3.0`.
   - Add a `CHANGELOG.md` entry:
    ```md
    ## 0.3.0

    My significant changes...
    ```
 - Push up the branch to Github: `git push origin release-v0.3.0`
 - Create a PR.
 - After merging the PR, push up the tag `v0.3.0`, (e.g. `git checkout main && git pull && git tag v0.3.0 && git push origin v0.3.0`)
 - Release automation will automatically pluck out the latest release notes, and use them as the body text for a Github Release.
