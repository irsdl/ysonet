# Source checkout without the research archive

The research archive is optional for building and running YSoNet. Use a partial
clone and sparse checkout to get the source and normal documentation while
leaving `docs/archived-references/` out of your working folder.

## Start a smaller checkout

Run with a current Git in PowerShell, Bash, or Zsh, in the parent directory where
you want the new `ysonet` folder:

```text
git clone --filter=blob:none --depth 1 --no-checkout https://github.com/irsdl/ysonet.git ysonet
cd ysonet
git sparse-checkout set --no-cone '/*' '!/docs/archived-references/'
git checkout master
```

Keep the quotes around the patterns. They mean "include everything except the
archive". All other source directories and root build files remain available.
Continue with [Building and testing](building-and-testing.md).

`--no-checkout` lets you select files before Git downloads their contents.
`--filter=blob:none` fetches file contents as needed, and `--depth 1` limits the
initial history. The server must support filtering; heed a warning that filtering
was ignored. Merely deleting the archive after a normal clone does not recover
its transfer cost or remove it from Git history. See Git's
[partial-clone options](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---filterltfilter-specgt).

## Read or download the archive later

Read the [archive online](https://github.com/irsdl/ysonet/tree/master/docs/archived-references)
without downloading it. Its index links to English Markdown and PDF copies,
original sources, and reports about missing or unreviewed material.
Local archive links in documentation will be unavailable in a sparse checkout.

To include the whole archive in this checkout:

```text
git sparse-checkout disable
```

Git fetches the omitted contents as needed. To omit it again, after saving any
edits inside the archive:

```text
git sparse-checkout set --no-cone '/*' '!/docs/archived-references/'
```

That removes clean archive files from the working folder, but does not discard
objects Git already downloaded. Commands that read archive history can also
fetch omitted content. Use a fresh partial clone when initial download size is
the concern. [Git documents sparse checkout separately from object storage](https://git-scm.com/docs/git-sparse-checkout).

A shallow clone omits older history. If you need it for contribution or release
comparison, run `git fetch --unshallow`. Leave the sparse selection in place to
keep the archive out of the working folder.

This workflow keeps the archive in its existing repository with stable paths.
It does not require a second repository or a separate archive release.
