addEventListener('fetch', event => {
  event.respondWith(
    new Response('Hello World', {
      headers: { 'content-type': 'text/plain' }
    })
  );
});