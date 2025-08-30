document.addEventListener('click', function (e) {
    fetch('/api/track_click', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            x: e.pageX,
            y: e.pageY,
            page: window.location.pathname,
            screen_width: window.innerWidth,
            screen_height: window.innerHeight
        })
    });
});
