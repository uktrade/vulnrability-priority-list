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

holiday_calendar_url = os.environ['HOLIDAY_CALENDAR_URL']
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


response = all_pages('''
query($after: String) {
  repository(owner:"uktrade", name:"data-workspace") {
    pullRequests(states:MERGED, first: 100, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
      edges {
        node {
          baseRefName
          title
          url
          createdAt
          closedAt
        }
      }
      pageInfo {
          hasNextPage
          endCursor
      }
    }
  }
}
''', {})

prs = response['data']['repository']['pullRequests']['edges']
now = datetime.datetime.now()
two_weeks_ago = now - datetime.timedelta(weeks=2, days=1)
recent_prs = [pr for pr in prs if datetime.datetime.fromisoformat(pr['node']['closedAt'][:-1]) >= two_weeks_ago]

for recent_pr in recent_prs:
    print(recent_pr['node']['createdAt'], recent_pr['node']['closedAt'])

lead_times = [datetime.datetime.fromisoformat(pr['node']['closedAt'][:-1]) - datetime.datetime.fromisoformat(pr['node']['createdAt'][:-1]) for pr in recent_prs]

print('num merged prs', len(lead_times))
print('min', min(lead_times))
print('mean', sum(lead_times, datetime.timedelta(0)) / len(lead_times))
print('median', statistics.median(lead_times))
print('max', max(lead_times))
