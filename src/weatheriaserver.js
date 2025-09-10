const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const apiKey = '6ba963b239ff7683a904b476e8e3bb61';  // openweathermap API Key

app.get('/search', async (req, res) => {
    const location = req.query.location;

    if (!location) {
        return res.status(400).json({ error: 'Location parameter is missing' });
    }

    try {
        console.log(`Searching for location: ${location}`);

        const geocodeUrl = `http://api.openweathermap.org/geo/1.0/direct?q=${location}&limit=1&appid=${apiKey}`;
        const geocodeResponse = await axios.get(geocodeUrl);

        if (!geocodeResponse.data || geocodeResponse.data.length === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        const { lat, lon, name } = geocodeResponse.data[0];

        if (typeof lat !== 'number' || typeof lon !== 'number') {
            return res.status(400).json({ error: 'Invalid latitude or longitude received' });
        }

        const weatherUrl = `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${apiKey}`;
        const weatherResponse = await axios.get(weatherUrl);

        const precipitationData = weatherResponse.data.rain ? weatherResponse.data.rain['1h'] : 0;

        const responseData = {
            lat,
            lon,
            location: name,
            precipitation: precipitationData || 0
        };

        res.json(responseData);

    } catch (error) {
        console.error('Error in API calls:', error.message || error.response?.data);
        
        if (error.response) {
            return res.status(error.response.status).json({
                error: 'Error fetching data from OpenWeatherMap',
                details: error.response.data
            });
        } else {
            return res.status(500).json({
                error: 'Internal Server Error',
                details: error.message || error.toString()
            });
        }
    }
});

const WEATHER_API_KEY = 'f853fc7b8382428da20232455241712'; 
const WEATHER_API_URL = 'http://api.weatherapi.com/v1/forecast.json';

app.get('/weather', async (req, res) => {
    const { city } = req.query;

    if (!city) {
        return res.status(400).json({ error: 'City name is required' });
    }

    try {
        console.log(`Fetching weather for city: ${city}`);
        const response = await axios.get(WEATHER_API_URL, {
            params: {
                key: WEATHER_API_KEY,
                q: city,
                days: 7
            }
        });

        console.log('WeatherAPI response:', JSON.stringify(response.data, null, 2));

        if (response.data && response.data.current) {
            res.json({
                name: response.data.location.name,
                region: response.data.location.region,
                country: response.data.location.country,
                temp: response.data.current.temp_c,
                description: response.data.current.condition.text,
                icon: response.data.current.condition.icon,
                localtime: response.data.location.localtime,
                forecast: response.data.forecast.forecastday.map(day => ({
                    date: day.date,
                    temp: day.day.avgtemp_c,
                    description: day.day.condition.text,
                    icon: day.day.condition.icon
                }))
            });
        } else {
            res.status(404).json({ error: 'Weather data not found' });
        }

    } catch (error) {
        console.error('Weather API Error:', error.message || error.response?.data);
        res.status(500).json({
            error: 'Error fetching weather data',
            details: error.response?.data || error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
