# Releasing

Published to [LuaRocks](https://luarocks.org/modules/lassosecurity/ai-lasso-guardrail)
as `ai-lasso-guardrail`; the rockspec is the single source of truth for the version.

1. **Bump** the rockspec in a reviewed PR: rename `ai-lasso-guardrail-X-Y.rockspec`
   and set `version = "X-Y"` + `source.tag = "X"`. Merge to `main`.
2. **Cut it**: Actions → **tag-release** → *Run workflow*. It tags the rockspec
   version and creates a GitHub Release. `ref` defaults to `main`; point it at an
   older branch/commit to cut a hotfix off an earlier point.
3. **tag-release** then calls **release.yml**, which runs `luarocks upload` to publish.

Requires the `LUAROCKS_API_KEY` secret. Versions are immutable — you can't re-publish
one, so **rollback = ship a new (higher) version of the reverted code** (bump, then run
the workflow, optionally from the older `ref`).
