# To publish a new release on luarocks

From: https://martin-fieber.de/blog/create-build-publish-modules-for-lua/

1. Merge pull requests
2. Update .rockspec filename with new version
3. Update .rockspec content with new version
4. Update all `_VERSION` in folder `lib` with new version
5. `luarocks install --deps-only lua-resty-jwt-verification-<VERSION>.rockspec`
6. `luarocks make`
7. Commit version changes
8. Create git tag for release: `git tag v<VERSION> && git push --tags`
9. `luarocks build`
10. `luarocks pack lua-resty-jwt-verification-<VERSION>.rockspec`
11. `luarocks upload lua-resty-jwt-verification-<VERSION>.rockspec --api-key=<API_KEY_HERE>`
