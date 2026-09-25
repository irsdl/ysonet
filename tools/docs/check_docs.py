#!/usr/bin/env python3
"""Offline checks for authored Markdown and required release notes (stdlib only)."""
import argparse
import html
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
SECTIONS = ('Highlights', 'Compatibility and upgrade', 'Known limitations', 'Validation')


def prose(text):
    """Remove comments and fenced/indented examples, preserving line numbers."""
    text = re.sub(r'<!--.*?-->', lambda m: '\n' * m[0].count('\n'), text, flags=re.S)
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^ {0,3}(`{3,}|~{3,})', line)
        if fence:
            if re.match(r'^ {0,3}' + re.escape(fence[0]) + '{' + str(len(fence)) + r',}\s*$', line):
                fence = None
            lines.append('')
        elif match:
            fence = match[1]
            lines.append('')
        else:
            lines.append('' if line.startswith(('    ', '\t')) else line)
    return '\n'.join(lines)


def anchors(text):
    text = prose(text)
    result = set(re.findall(r'<[^>]+\b(?:id|name)=["\']([^"\']+)["\']', text))
    used = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        heading = re.match(r'^ {0,3}#{1,6}\s+(.+?)(?:\s+#+\s*)?$', line)
        title = heading[1] if heading else None
        if not heading and i + 1 < len(lines) and line.strip() and re.fullmatch(r' {0,3}(?:=+|-+)\s*', lines[i + 1]):
            title = line.strip()
        if title is None:
            continue
        title = re.sub(r'!?\[([^\]]+)\]\([^)]*\)', r'\1', title)
        title = html.unescape(re.sub(r'<[^>]*>', '', title)).lower()
        title = re.sub(r'[^\w\-\s]', '', title).replace(' ', '-').replace('\t', '-')
        slug, number = title, 0
        while slug in used:
            number += 1
            slug = title + '-' + str(number)
        used.add(slug)
        result.add(slug)
    return result


def links(text):
    """Yield (line, destination) for inline, reference, image and HTML links.

    Balanced parentheses in inline destinations are supported. Code spans/examples
    and comments are excluded. This is a local-link checker, not a Markdown linter.
    """
    text = prose(text)
    # Code spans can contain brackets which are not links. Keep their line count.
    text = re.sub(r'(`+)(?!`)(.*?)(?<!`)\1(?!`)', lambda m: '\n' * m[0].count('\n'), text, flags=re.S)
    definitions = {}
    for match in re.finditer(r'^ {0,3}\[([^\]]+)\]:\s*(<[^>]+>|\S+)', text, re.M):
        definitions[' '.join(match[1].lower().split())] = match[2].strip('<>')
        yield text[:match.start()].count('\n') + 1, match[2].strip('<>')
    for match in re.finditer(r'(?<!\\)\[([^\]\n]+)\]', text):
        end, label = match.end(), match[1]
        line = text[:match.start()].count('\n') + 1
        if text[end:end + 1] == ':':
            continue
        if text[end:end + 1] == '(':
            start = end + 1
            while start < len(text) and text[start].isspace():
                start += 1
            if text[start:start + 1] == '<':
                close = text.find('>', start + 1)
                if close != -1:
                    yield line, text[start + 1:close]
                continue
            pos, depth = start, 0
            while pos < len(text):
                char = text[pos]
                if char == '\\':
                    pos += 2
                    continue
                if char == '(':
                    depth += 1
                elif char == ')':
                    if depth == 0:
                        break
                    depth -= 1
                elif char.isspace() and depth == 0:
                    break
                pos += 1
            yield line, re.sub(r'\\([()])', r'\1', text[start:pos])
        else:
            ref = re.match(r'\[([^\]]*)\]', text[end:])
            key = ' '.join(((ref[1] or label) if ref else label).lower().split())
            if key in definitions:
                yield line, definitions[key]
            elif ref:
                yield line, 'UNDEFINED-REFERENCE:' + key
    for match in re.finditer(r'<(?:a|img)\b[^>]*?\b(?:href|src)=["\']([^"\']+)["\']', text, re.I):
        yield text[:match.start()].count('\n') + 1, html.unescape(match[1])


def check_file(root, path):
    errors, count = [], 0
    for line, destination in links(path.read_text(encoding='utf-8-sig')):
        if destination.startswith('UNDEFINED-REFERENCE:'):
            errors.append(f'{path.relative_to(root)}:{line}: {destination}')
            continue
        parsed = urlsplit(html.unescape(destination))
        if parsed.scheme or parsed.netloc:
            continue
        count += 1
        target = (root / unquote(parsed.path).lstrip('/') if parsed.path.startswith('/')
                  else path.parent / unquote(parsed.path)) if parsed.path else path
        target = target.resolve()
        reason = None
        if not target.is_relative_to(root.resolve()):
            reason = 'link leaves the checkout'
        elif not target.exists():
            reason = 'missing path'
        elif parsed.fragment and target.suffix.lower() == '.md':
            if unquote(parsed.fragment) not in anchors(target.read_text(encoding='utf-8-sig')):
                reason = 'missing heading or HTML anchor'
        if reason:
            errors.append(f'{path.relative_to(root)}:{line}: {reason}: {destination}')
    return errors, count


def documentation_files(root):
    # Git excludes ignored research/work areas; include new public docs before commit.
    listed = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root)
    for name in sorted(set(listed.decode('utf-8').split('\0'))):
        path = Path(name)
        if path.suffix.lower() != '.md' or not (root / path).is_file():
            continue
        if name.startswith('docs/archived-references/'):
            continue  # Generated third-party source copies have their own archive tooling.
        if name in ('AGENTS.md', 'CLAUDE.md') or name.startswith('.claude/'):
            continue  # Agent/developer instructions are outside the user-documentation set.
        yield root / path


def release_notes(root, version):
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ValueError('expected a version like v2026.9.1')
    path = root / 'docs' / 'release-notes' / (version + '.md')
    if not path.is_file():
        raise ValueError(f'missing required release notes: docs/release-notes/{version}.md')
    text = path.read_text(encoding='utf-8-sig')
    visible = prose(text)
    if re.search(r'\b(?:TODO|TBD|FIXME)\b|\[insert\b|<VERSION>', visible, re.I):
        raise ValueError('release notes contain an unfinished template placeholder')
    headings = list(re.finditer(r'^##[ \t]+(.+?)[ \t]*$', visible, re.M))
    for title in SECTIONS:
        matches = [i for i, m in enumerate(headings) if m[1] == title]
        if len(matches) != 1:
            raise ValueError(f'release notes need exactly one "## {title}" section')
        i = matches[0]
        content = visible[headings[i].end():headings[i + 1].start() if i + 1 < len(headings) else len(visible)]
        content = re.sub(r'^#{1,6}[^\n]*$', '', content, flags=re.M)
        content = re.sub(r'<[^>]*>', '', content)
        if not any(char.isalnum() for char in content):
            raise ValueError(f'release notes have an empty "## {title}" section')
    if any(m[1] == "What's Changed" for m in headings):
        raise ValueError('GitHub supplies the What\'s Changed heading; omit it here')
    for _, destination in links(text):
        if not urlsplit(destination).scheme:
            raise ValueError('release notes must use absolute links so they work in the GitHub release: ' + destination)
    return text


def release_body(root, version):
    notes = release_notes(root, version)
    sponsors = (root / 'docs' / 'sponsors.md').read_text(encoding='utf-8-sig')
    if not re.search(r'^##[ \t]+Sponsors[ \t]*$', prose(sponsors), re.M):
        raise ValueError('docs/sponsors.md must contain ## Sponsors')
    return sponsors.rstrip() + '\n\n' + notes.strip() + '\n'


def normalize_body(text):
    return '\n'.join(line.rstrip() for line in text.replace('\r\n', '\n').splitlines()).strip()


def verify_published(expected, actual):
    if normalize_body(expected) not in normalize_body(actual):
        raise ValueError('published release body is missing or changed from the required sponsor and upgrade notes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('links', help='check local paths and Markdown anchors in public documentation')
    release = sub.add_parser('release', help='validate notes before creating a tag or publishing')
    release.add_argument('version')
    release.add_argument('--output', type=Path, help='write the validated complete release body')
    release.add_argument('--published', type=Path, help='verify a downloaded published body')
    args = parser.parse_args()
    try:
        if args.command == 'links':
            errors, files, count = [], 0, 0
            for path in documentation_files(ROOT):
                found, checked = check_file(ROOT, path)
                errors.extend(found)
                files += 1
                count += checked
            for error in errors:
                print(error, file=sys.stderr)
            print(f'Documentation: {files} files, {count} local links, {len(errors)} errors (external URLs not fetched).')
            return bool(errors)
        body = release_body(ROOT, args.version)
        if args.published:
            verify_published(body, args.published.read_text(encoding='utf-8-sig'))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(body, encoding='utf-8', newline='\n')
        print('Release notes validated: ' + args.version)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
