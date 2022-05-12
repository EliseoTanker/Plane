if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker
      .register("service-worker.js")
      .then(
        function (registration) {
          console.log("SW Registered!");
        },
        function (err) {
          console.log("ServiceWorker registration failed: ", err);
        }
      )
      .catch(function (err) {
        console.log(err);
      });
  });
} else {
  console.log("Service worker is not supported");
}
