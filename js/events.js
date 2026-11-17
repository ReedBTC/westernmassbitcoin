// Moves meetups whose end time has passed from "Upcoming" to "Past", so the
// site stays current between manual edits. The static HTML remains the
// fallback for visitors without JavaScript and for crawlers.
//
// Homepage: each upcoming .event-card carries data-end="<ISO 8601 end time>".
// Event pages: the end time is read from the JSON-LD "endDate".
(function () {
  var now = Date.now();

  function isOver(iso) {
    var t = Date.parse(iso);
    return !isNaN(t) && t < now;
  }

  function markPast(badge) {
    if (!badge) return;
    badge.classList.remove('badge-upcoming');
    badge.classList.add('badge-past');
    badge.textContent = 'Past';
  }

  function eventNumber(card) {
    var el = card.querySelector('.event-number');
    return el ? parseInt(el.textContent, 10) : 0;
  }

  // Homepage event lists
  var upcomingGrid = document.querySelector('.upcoming-events-wrapper .events-grid');
  var pastGrid = document.querySelector('.past-events-wrapper .events-grid');
  if (upcomingGrid && pastGrid) {
    upcomingGrid.querySelectorAll('.event-card[data-end]').forEach(function (card) {
      if (!isOver(card.getAttribute('data-end'))) return;
      card.classList.add('past-event');
      markPast(card.querySelector('.badge'));
      // Past list is newest first: insert before the first lower-numbered card.
      var n = eventNumber(card);
      var before = Array.prototype.find.call(
        pastGrid.querySelectorAll('.event-card'),
        function (c) { return eventNumber(c) < n; }
      );
      pastGrid.insertBefore(card, before || null);
    });

    if (!upcomingGrid.querySelector('.event-card')) {
      var note = document.createElement('p');
      note.className = 'events-empty';
      note.textContent = 'The next meetup date will be announced soon. Subscribe to hear about it first.';
      upcomingGrid.appendChild(note);
    }
  }

  // Individual event page
  var heroBadge = document.querySelector('.page-hero .badge-upcoming');
  var ld = document.querySelector('script[type="application/ld+json"]');
  if (heroBadge && ld) {
    try {
      var data = JSON.parse(ld.textContent);
      if (data.endDate && isOver(data.endDate)) markPast(heroBadge);
    } catch (e) { /* leave the static badge as is */ }
  }
})();
