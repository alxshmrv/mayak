# IEEE MAC assignment data

`ieee-ma.tsv` is a compact, generated snapshot of the public IEEE
Registration Authority MA-L, MA-M and MA-S listings. Маяк bundles the snapshot
so manufacturer lookup remains local and works without an internet connection.

Refresh it from the repository root:

```bash
npm run data:ieee
```

The source listings and their assignment types are published by the
[IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/).
The generated file records its snapshot date.
