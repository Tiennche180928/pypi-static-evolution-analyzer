    diff_parser.add_argument("--all-diffs", action="store_true", help="Compatibility option; all diffs are now always shown")
    diff_parser.add_argument("--pypi-clean", help="Fetch this package from PyPI as a comparison reference")
    diff_parser.add_argument("--pypi-version", help="Specific version to fetch from PyPI")
    diff_parser.add_argument("--report", help="Optional additional combined Markdown report")
    diff_parser.add_argument("--out-dir", help="Optional additional copies under DIR/package/version/version_changes.md")
    diff_parser.add_argument("--temp-dir", help="Parent directory for temporary extraction (default: system temp)")
    diff_parser.add_argument("--json", action="store_true", help="Output as JSON")
    diff_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    repo_root = Path(__file__).parent.resolve()
    cwd = Path.cwd().resolve()

    def resolve_sample_dir(custom_path=None) -> Path:
        if custom_path:
            p = Path(custom_path).resolve()
            if p.exists() and p.is_dir():
                return p
            print(f"Warning: Specified directory '{custom_path}' not found. Falling back to auto-detection.")

        candidates = [
            cwd / "pypi-samples",
            repo_root / "pypi-samples",
            cwd,
            repo_root,
        ]
        # Prefer directory that actually contains Python archive samples
        for cand in candidates:
            if cand.exists() and cand.is_dir():
                has_samples = any(
                    next(cand.glob(f"*{ext}"), None) is not None
                    for ext in [".tar.gz", ".tgz", ".whl", ".zip"]
                )
                if has_samples:
                    return cand

        # Fallback to first existing directory
        for cand in candidates:
            if cand.exists() and cand.is_dir() and cand.name != ".git":
                return cand
        return cwd

    active_dir = resolve_sample_dir(getattr(args, "target_dir", None))
    search_dirs = [
        active_dir,
        active_dir / "request-investigation",
        cwd / "pypi-samples",
        repo_root / "pypi-samples",
        cwd,
        repo_root,
    ]

    if args.command == "list":
        list_pypi_samples(active_dir)
        return

    if not args.command:
        parser.print_help()
        return

    try:
        temp_workspace = Path(tempfile.mkdtemp(prefix="pypi_analysis_", dir=getattr(args, "temp_dir", None)))
    except OSError as error:
        print("Error creating analysis temp directory {}: {}".format(getattr(args, "temp_dir", None) or tempfile.gettempdir(), error), file=sys.stderr)
        raise SystemExit(1)
    try:
        if args.command == "scan":
            sample_path = find_sample(args.sample, search_dirs)
            base_pkg = extract_package_base_name(args.sample)
            if sample_path and sample_path.is_dir():
                # A dataset package folder contains archives, not directly scannable source.
                dataset_versions = find_all_package_versions(base_pkg, search_dirs)
                if dataset_versions:
                    sample_path = dataset_versions[-1][1]
                    print("[*] Selected latest local version: {} ({})".format(dataset_versions[-1][0], sample_path))
                elif (sample_path / "src.zip").is_file():
                    sample_path = sample_path / "src.zip"
            if not sample_path:
                base_pkg = extract_package_base_name(args.sample)
                all_v = find_all_package_versions(base_pkg, search_dirs)
                if all_v:
                    sample_path = all_v[-1][1]
                    print(f"[*] Package '{base_pkg}' has {len(all_v)} versions. Scanning latest: v{all_v[-1][0]} ({sample_path.name})")
                else:
                    print(f"Error: Sample '{args.sample}' not found in pypi-samples.")
                    sys.exit(1)

            print(f"[*] Extracting and analyzing: {sample_path.name}")
            unpacked = extract_package(sample_path, temp_workspace / "target")
            findings = scan_package_dir(unpacked)

            if args.json:
                print(json.dumps([f.to_dict() for f in findings], indent=2))
            else:
                print_scan_report(findings, sample_path.name, args.no_color, count_python_sources(unpacked))

            if args.report:
                export_scan_report(Path(args.report), findings, str(sample_path), count_python_sources(unpacked))

        elif args.command == "diff":
            try:
                execute_diff_history(args, parser, search_dirs, cwd, temp_workspace)
            except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
                print("Error: " + str(error), file=sys.stderr)
                raise SystemExit(1)

    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)


if __name__ == "__main__":
    main()
