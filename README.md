# vulnerability-priority-list

A command line report on a GitHub organisation's repositories, ordered by priority, and including time-to-SLA for each severity level

![Screenshot of vulnerability-priority-list output of package vulnerabilities in priority order](screenshot.png)

## Features

- Calculates the SLA due dates based on working days: weekdays excluding public holidays.
- 😴 indicates the vulnerability has been dismissed in GitHub's UI.
- Links to GitHub's dependabot page are included for each repository. Links are dotted-underlined, and typically holding down CTRL or CMD while clicking will open the target page.

## Usage

- Copy [sample.env](sample.env) to `.env`, and populate variables as needed (more details in [sample.env](sample.env))

- Run

  ```python3
  pip install -r requirements.txt
  python3 scan.py
  ```

  At the time of writing, it takes around 15 seconds to run, making 8 requests to GitHub's API.
