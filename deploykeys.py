import datetime
from collections import defaultdict
from functools import cmp_to_key
import json
import os
import re
import statistics

from dotenv import load_dotenv
import requests
from rich import box
from rich.console import Console
from rich.table import Table

load_dotenv()

token = os.environ['GITHUB_TOKEN']
org_name = os.environ['GITHUB_ORG']
team_slug = os.environ['GITHUB_TEAM_SLUG']

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


repos = \
    all_pages('''
        query($org_name: String!, $after: String) {
            organization(login:$org_name) {
                repositories(first: 100, after: $after) {
                    nodes {
                        name
                        deployKeys(first: 100, after: $after) {
                            nodes {
                                createdAt
                                readOnly
                                title
                            }
                            pageInfo {
                                hasNextPage
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
                                    deployKeys(first: 100, after: $after) {
                                        nodes {
                                            createdAt
                                            readOnly
                                            title                                   
                                        }
                                        pageInfo {
                                            hasNextPage
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
repos_with_keys = [repo for repo in repos if repo['deployKeys']['nodes']]

table = Table(box=box.ASCII, header_style='not bold')
table.add_column("Repository")
table.add_column("Key created at")
table.add_column("Key read only")
table.add_column("Key title")

for repo_with_key in repos_with_keys: 
    for key in repo_with_key['deployKeys']['nodes']:
        table.add_row(
            f'[link=https://github.com/{org_name}/{repo_with_key["name"]}/settings/keys]{repo_with_key["name"]}[/link]',
            key['createdAt'],
            str(key['readOnly']),
            f'[link=https://app.circleci.com/settings/project/github/{org_name}/{repo_with_key["name"]}/ssh]{key["title"]}[/link]',
            style='bold bright_red' if datetime.datetime.fromisoformat(key['createdAt'][:-1]) < datetime.datetime.fromisoformat('2023-01-05') else 'bold bright_white',
        )

console = Console()
console.print(table)
