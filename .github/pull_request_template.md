**What changed, and why.** If it fixes a defect, say how the defect was shown.

- [ ] A wire-visible change has its SPEC.md edit in this pull request, and a protocol change is
      proposed in hdtp-spec.
- [ ] Tests come with the change, and each new test was seen failing on the code as it was.
- [ ] `make check`, `make analyze` and `make sqlc-check` are green (the pre-push hook runs them);
      `make web` was run and `web/dist` committed if `web/` changed.
- [ ] Touches a security path (`policy.Allow`, tier resolution, envelope validation order, the
      SSRF guard, audit writes, input caps): say which.
