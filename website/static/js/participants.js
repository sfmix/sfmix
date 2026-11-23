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
  const headers = thead.querySelectorAll('th');

  // Columns: 0=Org, 1=ASN, 2=Type, 3=Location, 4=Speed, 5=IPv4, 6=IPv6
  const COL_IPV4 = 5;

  // Each participant is its own <tbody> row group; sort by its first row.
  function getRowGroups() {
    return Array.from(table.tBodies);
  }

  function ipv4Value(text) {
    const parts = text.split('.').map(Number);
    if (parts.length === 4) {
      return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
    }
    return 0;
  }

  function sortValue(group, col) {
    const row = group.rows[0];
    if (!row) return '';
    if (col === 1) return parseInt(row.dataset.asn, 10) || 0;
    if (col === 4) return parseInt(row.dataset.speedBps, 10) || 0;
    if (col === 5) return ipv4Value(row.dataset.ipv4 || '');
    const cell = row.cells[col];
    return cell ? cell.textContent.trim().toLowerCase() : '';
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

    // Re-append row groups in sorted order
    groups.forEach(function (group) {
      table.appendChild(group);
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
