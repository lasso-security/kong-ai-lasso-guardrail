# Releasing

Published to [LuaRocks](https://luarocks.org/modules/lassosecurity/ai-lasso-guardrail)
as `ai-lasso-guardrail`; the rockspec is the single source of truth for the version.

1. **Bump** the rockspec in a reviewed PR: rename `ai-lasso-guardrail-X-Y.rockspec`
   and set `version = "X-Y"` + `source.tag = "X"`. Merge to `main`.
2. **Cut it**: Actions → **tag-release** → *Run workflow* (from `main`). It tags the
   rockspec version and creates a GitHub Release.
3. The tag triggers **release.yml**, which runs `luarocks upload` to publish.

Requires the `LUAROCKS_API_KEY` secret. Versions are immutable — never re-tag a
published version; bump instead.
