const nutCheckIntervalMsec = 1000;
const spinChars = [ '|', '/', '-', '\\' ];
let spinIndex = 0;
let sqrlNut;

$(document).ready(() => {
  // Get the SQRL nut from the page content.
  sqrlNut = $('#sqrl-nut').text();
  console.log(`Found SQRL nut ${sqrlNut}`);

  // Poll the back-end to see if a phone login has occurred.
  setTimeout(pollNut, nutCheckIntervalMsec);
});

function resetLoginText() {
  spinIndex = (spinIndex + 1) % spinChars.length;
  $('#login-text').text(spinChars[spinIndex]);
  setTimeout(pollNut, nutCheckIntervalMsec / 2);
}

function pollNut() {
  spinIndex = (spinIndex + 1) % spinChars.length;
  $('#login-text').text(spinChars[spinIndex] + ` Polling nut /pollNut/${sqrlNut}`);
  $.get({
    url: `/pollNut/${sqrlNut}`,
    cache: false,
    error: (jqXHR, textStatus, errorThrown) => {
      $("#login-text").text(`ERROR getting nut status: ${textStatus}: ${errorThrown}`);
      setTimeout(resetLoginText, nutCheckIntervalMsec / 2);
    },
    success: (data, textStatus, jqXHR) => {
      // Store the login cookie value and Redirect the page if the nut was logged in.
      // Data is a NutPollResult
      if (data && data.loggedIn) {
        $("#login-text").text(`Success! Browser stored updated cookie containing session. Redirecting to ${data.redirectTo} in a few seconds`);
        setTimeout(() => window.location.href = data.redirectTo, 4000);
      } else {
        // Normal case: No login.
        setTimeout(resetLoginText, nutCheckIntervalMsec / 2);
      }
    }
  });
}
