document.addEventListener('DOMContentLoaded', function () {
  // Pang Submission
  document.getElementById('weatherform').addEventListener('submit', async (event) => {
    event.preventDefault();

    const city = document.getElementById('city').value;
    const weatherInfo = document.getElementById('weatherinfo');
    const errorMessage = document.getElementById('errormessage');
    const forecastWeek = document.querySelector('.forecastweek');

    // Example JavaScript to add 'wait' class when needed
    document.body.classList.add('wait');  // Adds the loading cursor

    // To remove it when done:
    document.body.classList.remove('wait');


    document.body.style.cursor = 'url(assets/images/loading.png), auto';


    // Pang Clear
    weatherInfo.classList.add('hidden');
    errorMessage.classList.add('hidden');
    forecastWeek.innerHTML = ''; 
    document.getElementById('weathericon').innerHTML = ''; 

    try {
      const response = await fetch(`/weather?city=${encodeURIComponent(city)}`);
      const data = await response.json();

      if (response.ok) {
        weatherInfo.classList.remove('hidden');
        errorMessage.classList.add('hidden');

        if (data) {

          document.getElementById('weathercity').textContent = `Weather in ${data.name}`;
          document.getElementById('weatherregion').textContent = `Region/Province: ${data.region || 'N/A'}`;
          document.getElementById('weathercountry').textContent = `Country: ${data.country || 'N/A'}`;
          document.getElementById('weatherdescription').textContent = `Description: ${data.description || 'N/A'}`;
          document.getElementById('weathertemp').textContent = `Temperature: ${data.temp || 'N/A'}°C`;

          const iconElement = document.createElement('img');
          iconElement.src = data.icon || '/default-icon.png';
          iconElement.alt = data.description || 'Weather icon';
          document.getElementById('weathericon').appendChild(iconElement);

          // Time
          const cityTime = new Date(data.localtime).toLocaleString();
          document.getElementById('citytime').textContent = `City Time: ${cityTime}`;

          // Forecast
          if (Array.isArray(data.forecast)) {
            data.forecast.forEach(day => {
              const formattedDate = new Date(day.date).toLocaleDateString('en-US', { weekday: 'long' });
              const forecastDay = document.createElement('div');
              forecastDay.className = 'dayforecast';
              forecastDay.innerHTML = ` 
                <h3>${formattedDate}</h3>
                <img src="${day.icon || '/default-icon.png'}" alt="${day.description || 'Forecast icon'}">
                <p>${day.temp || 'N/A'}°C</p>
              `;
              forecastWeek.appendChild(forecastDay);
            });
          }

          const clientTime = new Date().toLocaleString();
          document.getElementById('clienttime').textContent = `Client Time: ${clientTime}`;

        } else {
          throw new Error('Unexpected information.');
        }
      } else {
        throw new Error(data.error || 'Failed to fetch weather data');
      }
    } catch (error) {
      errorMessage.classList.remove('hidden');
      errorMessage.textContent = error.message;
    }
  });

  // Toggles
  const currentBtn = document.getElementById('currentbutton');
  const dailyBtn = document.getElementById('dailybutton');
  const weatherMap = document.getElementById('weathermap')

  const currentSection = document.getElementById('currentsection');
  const dailySection = document.getElementById('dailysection');
  const mapSection = document.getElementById('mapSection');

  currentBtn.addEventListener('click', () => {
    setActiveSection(currentBtn, currentSection);
  });

  dailyBtn.addEventListener('click', () => {
    setActiveSection(dailyBtn, dailySection);
  });

  weatherMap.addEventListener('click', () => {
    setActiveSection(weatherMap, mapSection);
    if (!map) {
      initMap(lat, lon); 
  } 
    else {
      updateMap(lat, lon); 
  }
  });

  function setActiveSection(button, section) {
    // Remove Active Class
    document.querySelectorAll('.toolbarbuttons').forEach(btn => btn.classList.remove('active'));
    // For Active Class
    button.classList.add('active');

    // Hide all 
    document.querySelectorAll('.section').forEach(sec => sec.classList.add('hidden'));
    // Show section
    section.classList.remove('hidden');
  }

  // Dark Mode 
  const darkModeBtn = document.getElementById('darkmodebutton');
  const body = document.body;

  darkModeBtn.addEventListener('click', () => {
    body.classList.toggle('darkmode');
    
    if (body.classList.contains('darkmode')) {
      darkModeBtn.textContent = '🌞 Light Mode';
    } else {
      darkModeBtn.textContent = '🌝 Dark Mode';
    }
  });

  // Toggleschuchu
  const aboutToggleBtn = document.getElementById('abouttogglebutton');
  const aboutUsSection = document.getElementById('aboutus');

  if (aboutToggleBtn && aboutUsSection) {
    aboutToggleBtn.addEventListener('click', () => {
      // Pang visibility ng About Us section
      aboutUsSection.classList.toggle('hidden');
      
      // Select ONE Hide Others
      if (aboutUsSection.classList.contains('hidden')) {
        document.querySelectorAll('.abouttext').forEach(text => text.classList.remove('show'));
        document.querySelectorAll('.imagecontainer').forEach(image => image.classList.remove('show'));
      }
    });
  }

  // About Us Sections Togglebilities
  document.querySelectorAll('.aboutbutton').forEach(button => {
    button.addEventListener('click', (event) => {
      const sectionId = event.target.getAttribute('datasection');
      const section = document.getElementById(sectionId);
      const text = section.querySelector('.abouttext');

      if (text) {
        // Hide all except one being clicked 
        document.querySelectorAll('.abouttext').forEach(t => {
          if (t !== text) {
            t.classList.remove('show');
          }
        });
        document.querySelectorAll('.imagecontainer').forEach(img => {
          if (!text.contains(img)) {
            img.classList.remove('show');
          }
        });

        // for visibility of the clicked section
        text.classList.toggle('show');
        
        // for toggle visibility ng image containers inside the clicked section kasi baka di nanaman magtago
        const imageContainers = section.querySelectorAll('.imagecontainer');
        imageContainers.forEach(container => {
          container.classList.toggle('show');
        });
      }
    });
  });
});



  const submitButton = document.getElementById('submit');
  const locationInput = document.getElementById('city');
  let map;
  let precipitationLayer;
  let temperatureLayer;

  // Ensure the searchButton and locationInput exist in the DOM before adding event listeners
  if (submitButton && locationInput) {
      submitButton.addEventListener('click', () => {
          const location = locationInput.value;
          if (location) {
              fetch(`/search?location=${location}`)
                  .then(response => {
                      if (!response.ok) {
                          throw new Error(`Server error: ${response.statusText}`);
                      }
                      return response.json();
                  })
                  .then(data => {
                      console.log('Fetched Data:', data);

                      if (data.lat == null || data.lon == null || !data.location || data.precipitation == null) {
                          throw new Error('Missing required data in response');
                      }

                      const { lat, lon, location, precipitation } = data;

                      console.log(`Location: ${location}, Lat: ${lat}, Lon: ${lon}, Precipitation: ${precipitation}mm`);

                      resetMap();
                      updateMap(lat, lon);

                      document.getElementById('location-info').innerText = `Location: ${location}`;
                      document.getElementById('precipitation-info').innerText = `Precipitation in the last hour: ${precipitation} mm`;
                  })
                  .catch(err => {
                      console.error('Error fetching data:', err);
                      alert(`Failed to fetch location data. Error: ${err.message}`);
                  });
          } else {
              alert('Please enter a location');
          }
      });
  } else {
      console.error('searchButton or locationInput not found');
  }

  function resetMap() {
      if (map) {
          map.remove();
          document.getElementById('map').innerHTML = '';
          map = null;
      }
  }

  function initMap(lat, lon) {
      map = L.map('map').setView([lat, lon], 12);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          attribution: '&copy; OpenStreetMap contributors'
      }).addTo(map);

      
      const apiKey = '6ba963b239ff7683a904b476e8e3bb61';

      precipitationLayer = L.tileLayer(`https://tile.openweathermap.org/map/rain/{z}/{x}/{y}.png?appid=${apiKey}`, {
          attribution: '&copy; OpenWeatherMap',
          maxZoom: 19,
          opacity: 0.8, 
          zIndex: 10    
      });

      temperatureLayer = L.tileLayer(`https://tile.openweathermap.org/map/temp/{z}/{x}/{y}.png?appid=${apiKey}`, {
          attribution: '&copy; OpenWeatherMap',
          maxZoom: 19,
          opacity: 0.8, 
          zIndex: 10    
      });

      L.marker([lat, lon]).addTo(map)
          .bindPopup(`Location: (${lat}, ${lon})`)
          .openPopup();
  }

  function updateMap(lat, lon) {
      if (!map) {
          initMap(lat, lon);
      } else {
          map.setView([lat, lon], 12);
          L.marker([lat, lon]).addTo(map)
              .bindPopup(`Location: (${lat}, ${lon})`)
              .openPopup();
      }
  }

  
  const togglePrecipitationButton = document.getElementById('toggle-precipitation');
  const toggleTemperatureButton = document.getElementById('toggle-temperature');

  if (togglePrecipitationButton) {
      togglePrecipitationButton.addEventListener('click', () => {
          if (map && precipitationLayer) {
              if (map.hasLayer(precipitationLayer)) {
                  map.removeLayer(precipitationLayer);
                  console.log('Removed precipitation layer');
              } else {
                  map.addLayer(precipitationLayer);
                  console.log('Added precipitation layer');
              }
          }
      });
  }

  if (toggleTemperatureButton) {
      toggleTemperatureButton.addEventListener('click', () => {
          if (map && temperatureLayer) {
              if (map.hasLayer(temperatureLayer)) {
                  map.removeLayer(temperatureLayer);
                  console.log('Removed temperature layer');
              } else {
                  map.addLayer(temperatureLayer);
                  console.log('Added temperature layer');
              }
          }
      });
  }


