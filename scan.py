import argparse
import csv
import datetime
import sys
from collections import defaultdict
from functools import cmp_to_key
import json
import os
import re

from dotenv import load_dotenv
import requests
from rich import box
from rich.console import Console
from rich.table import Table

load_dotenv()

holiday_calendar_url = os.environ['HOLIDAY_CALENDAR_URL']
token = os.environ['GITHUB_TOKEN']
org_name = os.environ['GITHUB_ORG']
team_slug = os.environ['GITHUB_TEAM_SLUG']
topic_to_filter = os.environ.get('GITHUB_TOPIC', '')

due_days = {
    'LOW': (0, 'LOW'),  # Logic below means LOW has no due date
    'MODERATE': (10, 'HIGH'),
    'HIGH': (5, 'CRITICAL'),
    'CRITICAL': (1, 'CRITICAL BREACH'),
}
severity_labels = {
    'LOW': 'LOW',
    'MODERATE': 'MODERATE',
    'HIGH': 'HIGH',
    'CRITICAL': 'CRITICAL',
    'CRITICAL BREACH': '⚠️  CRITICAL BREACH ⚠️ ',
}

def effective_severity(original_severity, due_date, today):
    if original_severity == 'LOW':
        return 'LOW'

    effective_severity = original_severity
    effective_severity_due_date = due_date
    for severity, (_, next_severity) in due_days.items():
        if severity == effective_severity and effective_severity_due_date < today:
            effective_severity = next_severity
            effective_severity_due_date = working_days_after(
                effective_severity_due_date,
                0 if next_severity == 'CRITICAL BREACH' else \
                due_days[next_severity][0]
            )

    return effective_severity

def submit(query, variables):
    response = requests.post('https://api.github.com/graphql', headers={
            'authorization': 'bearer ' + token,
        },
        data=json.dumps({'query': query, 'variables': variables}),
    )
    if response.status_code != 200 or 'errors' in json.loads(response.content):
        raise Exception(response.text)
    return json.loads(response.text)

def all_pages(query, variables):
    def _merge(dict_1, dict_2):
        # Recursive, but we don't expect crazy heavy nesting level

        list_keys = [key for key in dict_2.keys() if isinstance(dict_2[key], list)]
        merged_lists = {
            key: dict_1.get(key, []) + dict_2[key]
            for key in list_keys
        }

        dict_keys = [key for key in dict_2.keys() if isinstance(dict_2[key], dict)]
        merged_dicts = {
            key: _merge(dict_1.get(key, {}), dict_2[key])
            for key in dict_keys
        }

        return {
            **dict_1,
            **dict_2,
            **merged_lists,
            **merged_dicts,
        }

    def find_matching(struct, key):
        if isinstance(struct, dict):
            for k, v in struct.items():
                if k == key:
                    yield v
                else:
                    yield from find_matching(v, key)

        if isinstance(struct, list):
            for v in struct:
                yield from find_matching(v, key)

    results_all = {}
    page_info ={
        'hasNextPage': True,
        'endCursor': None,
    }

    while page_info['hasNextPage']:
        results_this_page = submit(query, {
            **variables,
            f'after': page_info['endCursor'],
        })
        page_info = list(find_matching(results_this_page, 'pageInfo'))[-1]
        results_all = _merge(results_all, results_this_page)

    return results_all

holiday_days = set([
    datetime.datetime.strptime(date_str, '%Y%m%d').date()
    for date_str in re.findall(
        r'^DTSTART;VALUE=DATE:(\d+)',
        requests.get(holiday_calendar_url).text,
        re.MULTILINE
    )
])
# Rough paranoia check
if len(holiday_days) < 10:
    raise Exception('Unable to find enough holiday days')

def working_days_after(date, days):
    while days:
        date = date + datetime.timedelta(days=1)
        if date.weekday() not in {5, 6} and date not in holiday_days:
            days -= 1
    return date

repos_all = \
    all_pages('''
        query($org_name: String!, $after: String) {
            organization(login:$org_name) {
                repositories(first: 100, after: $after) {
                    nodes {
                        name
                        isArchived
                        vulnerabilityAlerts(first: 100) {
                            nodes {
                                createdAt
                                fixedAt
                                dismissedAt
                                securityVulnerability {
                                    severity
                                    advisory {
                                        withdrawnAt
                                    }
                                    package {
                                        name
                                        ecosystem
                                    }
                                    firstPatchedVersion {
                                        identifier
                                    }
                                }
                            }
                            pageInfo {
                                hasNextPage
                            }
                        }
                        repositoryTopics(first: 100) {
                            edges {
                                node {
                                    topic {
                                        name
                                    }
                                }
                            }
                        }
                    }
                    pageInfo {
                      hasNextPage
                      endCursor
                    }
                }
            }
        }
    ''', {'org_name': org_name}
    )['data']['organization']['repositories']['nodes'] if not team_slug else \
    [
        edge['node']
        for edge in all_pages('''
            query($org_name: String!, $team_slug: String!, $after: String) {
                organization(login:$org_name) {
                    team(slug: $team_slug) {
                        repositories(first: 100, after: $after) {
                            edges {
                                node {
                                    name
                                    isArchived
                                    vulnerabilityAlerts(first: 100) {
                                        nodes {
                                            createdAt
                                            fixedAt
                                            dismissedAt
                                            securityVulnerability {
                                                severity
                                                advisory {
                                                    withdrawnAt
                                                }
                                                package {
                                                    name
                                                    ecosystem
                                                }
                                                firstPatchedVersion {
                                                    identifier
                                                }
                                            }
                                        }
                                        pageInfo {
                                            hasNextPage
                                        }
                                    }
                                    repositoryTopics(first: 100) {
                                        edges {
                                            node {
                                                topic {
                                                    name
                                                }
                                            }
                                        }
                                    }
                                }
                                permission
                            }
                            pageInfo {
                                hasNextPage
                                endCursor
                            }
                        }
                    }
                }
            }
        ''', {'org_name': org_name, 'team_slug': team_slug})['data']['organization']['team']['repositories']['edges']
        if edge['permission'] == 'ADMIN'
    ]
repos_not_archived = [repo for repo in repos_all if not repo['isArchived']]

repos_with_single_page_of_vulns = {
    repo['name']: repo
    for repo in repos_not_archived
    if not repo['vulnerabilityAlerts']['pageInfo']['hasNextPage']
}
repo_names_with_single_page_of_vulns = set(repos_with_single_page_of_vulns.keys())

repos_with_all_vulns = {
    **repos_with_single_page_of_vulns,
    **{
        repo['name']: {
            **repo,
            'vulnerabilityAlerts': {
                'nodes': all_pages('''
                    query($org_name: String!, $repo_name: String!, $after: String) {
                        organization(login: $org_name) {
                            repository(name: $repo_name) {
                                vulnerabilityAlerts(first: 100, after: $after) {
                                    nodes {
                                        createdAt
                                        fixedAt
                                        dismissedAt
                                        securityVulnerability {
                                            severity
                                            advisory {
                                                withdrawnAt
                                            }
                                            package {
                                                name
                                                ecosystem
                                            }
                                            firstPatchedVersion {
                                                identifier
                                            }
                                        }
                                    }
                                    pageInfo {
                                        hasNextPage
                                        endCursor
                                    }
                                }
                            }
                        }
                    }
                ''', {'org_name': org_name, 'repo_name': repo['name']})['data']['organization']['repository']['vulnerabilityAlerts']['nodes']
            }
        }
        for repo in repos_not_archived
        if repo['name'] not in repo_names_with_single_page_of_vulns
    }
}

# Group by vulnrability
vulns = defaultdict(lambda: {
    'package_name': None,
    'first_patched_version': None,
    'original_severity': None,
    'repo_alerts': []
})
today = datetime.datetime.now().date()
for repo_name, repo in repos_with_all_vulns.items():
    repo_alerts = repo['vulnerabilityAlerts']['nodes']
    repo_topics_names = set(
        topic_edge['node']['topic']['name']
        for topic_edge in repo['repositoryTopics']['edges']
    )

    if topic_to_filter and topic_to_filter not in repo_topics_names:
        continue

    for repo_alert in repo_alerts:
        if repo_alert['fixedAt'] is None or repo_alert['fixedAt'] < '2024-01-23T00:00:00Z':
            # At the time of writing, it doesn't look like GitHub's API offers filtering on
            # properties of alerts, so we exclude fixed alerts in code
            continue
        print(repo_alert['fixedAt'])

        vuln = repo_alert['securityVulnerability']
        if vuln['advisory']['withdrawnAt'] is not None:
            continue

        package = vuln['package']
        severity = vuln['severity']
        first_patched_version = vuln['firstPatchedVersion']
        first_patched_version = \
            'None' if first_patched_version is None else \
            first_patched_version['identifier']
        published_at_date_str = repo_alert['createdAt'][:10]
        published_at_date = datetime.datetime.strptime(published_at_date_str, "%Y-%m-%d").date()
        due_date = working_days_after(published_at_date, due_days[severity][0])

        vuln_id = (
            package["name"].lower(),
            package["ecosystem"].lower(),
            first_patched_version,
            severity,
            due_date,
        )

        due_in_days = (due_date - today).days

        vulns[vuln_id]['package_name'] = package['name'].lower()
        vulns[vuln_id]['first_patched_version'] = first_patched_version
        vulns[vuln_id]['due_date'] = due_date
        vulns[vuln_id]['original_severity'] = severity
        vulns[vuln_id]['effective_severity'] = effective_severity(severity, due_date, today)
        vulns[vuln_id]['due_in_days'] = due_in_days
        vulns[vuln_id]['in_breach'] = severity != 'LOW' and due_in_days < 0
        vulns[vuln_id]['repo_alerts'].append((repo_alert['dismissedAt'] is not None, repo_name))
        vulns[vuln_id]['repo_topics'] = "; ".join(repo_topics_names)

# Convert to a flat list
def cmp_vulns(vuln_a, vuln_b):
    sev_a = vuln_a['effective_severity']
    sev_b = vuln_b['effective_severity']
    orig_sev_a = vuln_a['original_severity']
    orig_sev_b = vuln_b['original_severity']
    due_in_days_a = vuln_a['due_in_days']
    due_in_days_b = vuln_b['due_in_days']
    in_breach_a = vuln_a['in_breach']
    in_breach_b = vuln_b['in_breach']

    # In breach always above not in breach
    if in_breach_a and not in_breach_b:
        return -1
    if in_breach_b and not in_breach_a:
        return 1

    # If both in breach, first order by effective severity, then original severity, then due date
    if in_breach_a and in_breach_b:
        if sev_a == 'CRITICAL BREACH' and sev_b != 'CRITICAL BREACH':
            return -1
        if sev_b == 'CRITICAL BREACH' and sev_a != 'CRITICAL BREACH':
            return 1
        if sev_a == 'CRITICAL' and sev_b != 'CRITICAL':
            return -1
        if sev_b == 'CRITICAL' and sev_a != 'CRITICAL':
            return 1
        if sev_a == 'HIGH' and sev_b != 'HIGH':
            return -1
        if sev_b == 'HIGH' and sev_a != 'HIGH':
            return 1
        if sev_a == 'MODERATE' and sev_b != 'MODERATE':
            return -1
        if sev_b == 'MODERATE' and sev_a != 'MODERATE':
            return 1

        if orig_sev_a == 'CRITICAL' and orig_sev_b != 'CRITICAL':
            return -1
        if orig_sev_b == 'CRITICAL' and orig_sev_a != 'CRITICAL':
            return 1
        if orig_sev_a == 'HIGH' and orig_sev_b != 'HIGH':
            return -1
        if orig_sev_b == 'HIGH' and orig_sev_a != 'HIGH':
            return 1
        if orig_sev_a == 'MODERATE' and orig_sev_b != 'MODERATE':
            return -1
        if orig_sev_b == 'MODERATE' and orig_sev_a != 'MODERATE':
            return 1
        if due_in_days_a < due_in_days_b:
            return -1
        if due_in_days_b < due_in_days_a:
            return 1

    # Not in breach, low is always at the bottom, then order by date, then severity
    if not in_breach_a and not in_breach_b:
        if orig_sev_a == 'LOW' and orig_sev_b != 'LOW':
            return 1
        if orig_sev_b == 'LOW' and orig_sev_a != 'LOW':
            return -1
        if due_in_days_a < due_in_days_b:
            return -1
        if due_in_days_b < due_in_days_a:
            return 1
        if orig_sev_a == 'CRITICAL' and orig_sev_b != 'CRITICAL':
            return -1
        if orig_sev_b == 'CRITICAL' and orig_sev_a != 'CRITICAL':
            return 1
        if orig_sev_a == 'HIGH' and orig_sev_b != 'HIGH':
            return -1
        if orig_sev_b == 'HIGH' and orig_sev_a != 'HIGH':
            return 1
        if orig_sev_a == 'MODERATE' and orig_sev_b != 'MODERATE':
            return -1
        if orig_sev_b == 'MODERATE' and orig_sev_a != 'MODERATE':
            return 1

    # Just for consistency really
    if vuln_a['package_name'] < vuln_b['package_name']:
        return -1
    if vuln_b['package_name'] < vuln_a['package_name']:
        return 1
    if vuln_a['first_patched_version'] < vuln_b['first_patched_version']:
        return -1
    if vuln_b['first_patched_version'] < vuln_a['first_patched_version']:
        return 1
    return 0


def get_deadline_text(vuln):
    return 'No deadline' if vuln['original_severity'] == 'LOW' else (
        vuln['due_date'].strftime("%-d %b") + (
            ' (in {} days)'.format(vuln['due_in_days']) if vuln['due_in_days'] >= 2 else \
            ' (tomorrow)' if vuln['due_in_days'] == 1 else \
            ' (today)' if vuln['due_in_days'] == 0 else \
            ' (yesterday)' if vuln['due_in_days'] == -1 else \
            ' ({} days ago)'.format(-vuln['due_in_days'])
    ))


def print_table(vulnerabilities):
    table = Table(box=box.ASCII, header_style='not bold')
    table.add_column("Package")
    table.add_column("must be bumped to")
    table.add_column("by")
    table.add_column("in repositories")
    table.add_column("with effective severity")

    for vuln in vulnerabilities:
        table.add_row(
            vuln['package_name'],
            vuln['first_patched_version'],
            get_deadline_text(vuln),
            '\n'.join([
                f'[link=https://github.com/{org_name}/{repo}/security/dependabot]{repo}[/link]' if not is_closed else \
                    f'😴 [not bold][link=https://github.com/{org_name}/{repo}/security/dependabot?q=is%3Aclosed]{repo}[/link][/not bold]'
                for is_closed, repo in sorted(set(vuln['repo_alerts']))
            ]),
            severity_labels[vuln['effective_severity']] + (
                ' (original: ' + severity_labels[vuln['original_severity']] + ')' if vuln[
                    'in_breach'] else ''),
            style= \
                'bold bright_red' if vuln['effective_severity'] in ['CRITICAL',
                                                                    'CRITICAL BREACH'] else \
                    'bold bright_white',
        )

    console = Console()
    console.print(table)


def print_csv(vulnerabilities):
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "package_name",
            "first_patched_version",
            "deadline",
            "repositories",
            "severity",
            "github_topics",
        ],
    )
    writer.writeheader()
    for vuln in vulnerabilities:
        non_closed_repos = sorted(set([repo for is_closed, repo in vuln['repo_alerts'] if not is_closed]))
        #if not non_closed_repos:
            #continue
        writer.writerow({
            "package_name": vuln['package_name'],
            "first_patched_version": vuln['first_patched_version'],
            "deadline": get_deadline_text(vuln),
            "repositories": '\n'.join([
                f'https://github.com/{org_name}/{repo}/security/dependabot/' for repo in non_closed_repos
            ]),
            "severity": vuln['effective_severity'],
            "github_topics": vuln['repo_topics'],
        })


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument(
        '--output',
        default='table',
        const='table',
        nargs='?',
        choices=['table', 'csv'],
        help='Output format of the script (default: %(defaults))'
    )
    args = parser.parse_args()

    vulns = list(vulns.values())
    if args.output == 'csv':
        print_csv(sorted(vulns, key=lambda x: x['due_date']))
    else:
        print_table(sorted(vulns, key=cmp_to_key(cmp_vulns)))


