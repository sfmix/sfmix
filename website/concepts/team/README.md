# /team/ page concepts

Three takes on a denser /team/ page, operations first, with roles as metadata on
each person (`src/people.js`) rather than one section per person, so Matt
Peterson is one record listed under both operations and the board.

- `src/*.frag.html` – one fragment per concept, plus the overview
- `src/people.js` – the shared records; would become `website/data/team.yaml`
- `build.py SITE_DIR OUT_DIR` – wraps fragments in the real site shell

Published for IX Administrators at https://www-staging.sfmix.org/team-concepts/
(`website/build-staging.sh`, deployed by `ansible/deploy_www_staging.playbook.yml`).
Local preview: `./build-staging.sh` in `website/`, then open
`.staging/team-concepts/index.html`.
