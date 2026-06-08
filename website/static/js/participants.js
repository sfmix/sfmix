// Sort mobile participant cards by IPv4
(function () {
  var container = document.querySelector('.participants-mobile');
  if (container) {
    var cards = Array.from(container.querySelectorAll('.participant-card'));
    cards.sort(function (a, b) {
      var aIP = (a.getAttribute('data-ipv4') || '').split('.').map(Number);
      var bIP = (b.getAttribute('data-ipv4') || '').split('.').map(Number);
      var aVal = aIP.length === 4 ? ((aIP[0] << 24) + (aIP[1] << 16) + (aIP[2] << 8) + aIP[3]) >>> 0 : 0;
      var bVal = bIP.length === 4 ? ((bIP[0] << 24) + (bIP[1] << 16) + (bIP[2] << 8) + bIP[3]) >>> 0 : 0;
      return aVal - bVal;
    });
    cards.forEach(function (card) { container.appendChild(card); });
  }
})();

// Sortable participants table
(function () {
  var table = document.querySelector('.participants-desktop table');
  if (!table) return;

  const thead = table.querySelector('thead');
  const tbody = table.querySelector('tbody');
  const headers = thead.querySelectorAll('th');

  // Map column index to sort key
  // Columns: 0=Org, 1=ASN, 2=Type, 3=Location, 4=Speed, 5=IPv4, 6=IPv6
  const COL_IPV4 = 5;

  // Group rows by rowspan (multi-port participants share cells via rowspan)
  function getRowGroups() {
    const groups = [];
    const rows = Array.from(tbody.querySelectorAll('tr'));
    let i = 0;
    while (i < rows.length) {
      const firstCell = rows[i].querySelector('td');
      const span = firstCell ? parseInt(firstCell.getAttribute('rowspan') || '1', 10) : 1;
      groups.push(rows.slice(i, i + span));
      i += span;
    }
    return groups;
  }

  // Extract sort value from a row group for a given column
  function sortValue(group, col) {
    // For rowspanned columns (0-2), always use first row
    // For per-port columns (3-6), use first row
    const row = group[0];
    const cells = row.querySelectorAll('td');
    // Adjust cell index: rows after the first in a group lack the rowspanned cells
    const cell = cells[col];
    if (!cell) return '';
    const text = cell.textContent.trim();

    // Numeric sort for ASN
    if (col === 1) return parseInt(text, 10) || 0;

    // Speed: parse to Mbps for numeric sort
    if (col === 4) {
      const m = text.match(/([\d.]+)\s*(G|M|T)/i);
      if (m) {
        const val = parseFloat(m[1]);
        const unit = m[2].toUpperCase();
        if (unit === 'T') return val * 1000000;
        if (unit === 'G') return val * 1000;
        return val;
      }
      return 0;
    }

    // IPv4: sort numerically by octets
    if (col === 5) {
      const parts = text.split('.').map(Number);
      if (parts.length === 4) {
        return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
      }
      return 0;
    }

    // IPv6: normalize for lexicographic sort
    if (col === 6) return text.toLowerCase();

    // Default: case-insensitive string
    return text.toLowerCase();
  }

  let currentCol = -1;
  let ascending = true;

  function sortTable(col) {
    if (currentCol === col) {
      ascending = !ascending;
    } else {
      currentCol = col;
      ascending = true;
    }

    // Update header indicators
    headers.forEach(function (th, i) {
      th.classList.remove('sort-asc', 'sort-desc');
      if (i === col) th.classList.add(ascending ? 'sort-asc' : 'sort-desc');
    });

    const groups = getRowGroups();
    groups.sort(function (a, b) {
      const va = sortValue(a, col);
      const vb = sortValue(b, col);
      let cmp = 0;
      if (typeof va === 'number' && typeof vb === 'number') {
        cmp = va - vb;
      } else {
        cmp = String(va).localeCompare(String(vb));
      }
      return ascending ? cmp : -cmp;
    });

    // Re-append rows in sorted order
    groups.forEach(function (group) {
      group.forEach(function (row) {
        tbody.appendChild(row);
      });
    });
  }

  // Make headers clickable
  headers.forEach(function (th, i) {
    th.style.cursor = 'pointer';
    th.setAttribute('title', 'Click to sort');
    th.addEventListener('click', function () {
      sortTable(i);
    });
  });

  // Default sort: IPv4
  sortTable(COL_IPV4);
})();
