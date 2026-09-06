from ai_security_review.diff import ExclusionRules, build_bundle, parse_section, split_diff_sections


def test_bundle_filters_generated_and_docs_kept(sample_diff):
    b = build_bundle(sample_diff)
    assert "gen/api.pb.go" in b.excluded          # generated marker
    assert "app/api/users.py" in b.paths
    assert "README.md" in b.paths                  # docs stay in the diff; findings there are filtered later
    assert "vendor/lib.js" in b.paths              # only excluded when the user asks


def test_exclude_dirs(sample_diff):
    b = build_bundle(sample_diff, ExclusionRules(["vendor", "./gen"]))
    assert "vendor/lib.js" in b.excluded
    assert "vendor/lib.js" not in b.text
    assert "app/api/users.py" in b.text


def test_exclusion_rules_matching():
    r = ExclusionRules(["node_modules", "third_party/vendor"])
    assert r.is_excluded("node_modules/x/y.js")
    assert r.is_excluded("pkg/node_modules/x.js")
    assert r.is_excluded("third_party/vendor/a.c")
    assert not r.is_excluded("third_party/a.c")
    assert not r.is_excluded("src/node_modules_helper.py")
    assert r.is_excluded("package-lock.json")
    assert r.is_excluded("dist/app.min.js")


def test_parse_section_line_numbers(sample_diff):
    sections = split_diff_sections(sample_diff)
    users = parse_section(sections[0])
    assert users.path == "app/api/users.py"
    assert users.status == "modified"
    assert users.additions == 7
    assert users.deletions == 0
    # first added line is line 13 in the new file (hunk starts at 10, three context lines)
    assert users.added_lines[0] == 13
    assert 15 in users.added_lines


def test_parse_added_and_deleted():
    added = parse_section("diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+a\n+b\n")
    assert added.status == "added" and added.additions == 2
    deleted = parse_section("diff --git a/old.py b/old.py\ndeleted file mode 100644\n--- a/old.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n")
    assert deleted.status == "deleted" and deleted.path == "old.py"


def test_truncation_marks_bundle():
    big = "diff --git a/big.py b/big.py\n--- a/big.py\n+++ b/big.py\n@@ -1 +1,1000 @@\n" + "".join(f"+line {i}\n" for i in range(5000))
    b = build_bundle(big, max_chars=2000)
    assert b.truncated
    assert "[patch truncated for size]" in b.text


def test_empty_diff():
    b = build_bundle("")
    assert b.is_empty()
