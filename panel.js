document.querySelectorAll('.actions').forEach(form => {
    form.addEventListener('submit', event => {
        if (event.submitter?.value === 'delete') {
            const username = form.elements.username.value;
            if (!window.confirm(`Delete the proxy account ${username}?`)) {
                event.preventDefault();
            }
        }
    });
});
