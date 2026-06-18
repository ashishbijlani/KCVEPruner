# KCVEPruner
Pruning Linux Kernel CVEs based on code reachability analysis 

# Fetch all CVEs from NVD

*NOTE* hardcoded to fetch for last 2196 days
```
python3 fetch_all_cves.py
```

# Filter CVEs based on build-time info

```
python3 measure.py <path-to-kernel-CVEs.csv> --kernel-source <path-to-linux-source> --kernel-build <path-to-linux-build> --output-dir cve_compiled_results
```

# Feedback and contrributions welcome

This is a work in progress and we welcome any feedback and code contributions.
