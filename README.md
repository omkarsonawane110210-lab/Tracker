# Tracker
// server.js
const express = require('express');
const mongoose = require('mongoose');
const twilio = require('twilio');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// MongoDB Schema
const userSchema = new mongoose.Schema({
  phoneNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  location: {
    latitude: Number,
    longitude: Number,
    timestamp: Date
  },
  isSharing: { type: Boolean, default: false }
});

const trackingSessionSchema = new mongoose.Schema({
  trackerPhone: String,
  targetPhone: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const TrackingSession = mongoose.model('TrackingSession', trackingSessionSchema);

// Twilio configuration
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { phoneNumber, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ phoneNumber, password: hashedPassword });
    
    await user.save();
    
    // Send verification SMS
    await twilioClient.messages.create({
      body: 'Your location tracking account has been created successfully.',
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { phoneNumber, password } = req.body;
    
    const user = await User.findOne({ phoneNumber });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    res.json({ token, user: { phoneNumber: user.phoneNumber } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update Location
app.post('/location/update', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    
    await User.findByIdAndUpdate(req.user.userId, {
      location: {
        latitude,
        longitude,
        timestamp: new Date()
      }
    });
    
    res.json({ message: 'Location updated successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Start Tracking Session
app.post('/tracking/start', authenticateToken, async (req, res) => {
  try {
    const { targetPhoneNumber } = req.body;
    const tracker = await User.findById(req.user.userId);
    
    // Check if target user exists
    const targetUser = await User.findOne({ phoneNumber: targetPhoneNumber });
    if (!targetUser) {
      return res.status(404).json({ error: 'Target user not found' });
    }
    
    // Create tracking session
    const trackingSession = new TrackingSession({
      trackerPhone: tracker.phoneNumber,
      targetPhone: targetPhoneNumber
    });
    
    await trackingSession.save();
    
    // Send notification to target user
    await twilioClient.messages.create({
      body: `${tracker.phoneNumber} wants to track your location. They will be able to see your location until you disable sharing.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: targetPhoneNumber
    });
    
    res.json({ message: 'Tracking session started', sessionId: trackingSession._id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get Location by Phone Number
app.get('/location/:phoneNumber', authenticateToken, async (req, res) => {
  try {
    const { phoneNumber } = req.params;
    const tracker = await User.findById(req.user.userId);
    
    // Check if tracking session exists and is authorized
    const trackingSession = await TrackingSession.findOne({
      trackerPhone: tracker.phoneNumber,
      targetPhone: phoneNumber,
      isActive: true
    });
    
    if (!trackingSession) {
      return res.status(403).json({ error: 'Not authorized to track this user' });
    }
    
    const targetUser = await User.findOne({ phoneNumber });
    if (!targetUser || !targetUser.location) {
      return res.status(404).json({ error: 'Location not available' });
    }
    
    res.json({
      phoneNumber: targetUser.phoneNumber,
      location: targetUser.location,
      isSharing: targetUser.isSharing
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Toggle Location Sharing
app.post('/sharing/toggle', authenticateToken, async (req, res) => {
  try {
    const { isSharing } = req.body;
    
    await User.findByIdAndUpdate(req.user.userId, { isSharing });
    
    res.json({ 
      message: `Location sharing ${isSharing ? 'enabled' : 'disabled'}`,
      isSharing 
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Middleware for authentication
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
}

// Start server
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    app.listen(3000, () => {
      console.log('Server running on port 3000');
    });
  })
  .catch(error => {
    console.error('Database connection error:', error);
  }); 
  // App.js
import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, Button, StyleSheet, Alert } from 'react-native';
import MapView, { Marker } from 'react-native-maps';
import * as Location from 'expo-location';

const API_BASE_URL = 'http://your-server-url:3000';

export default function LocationTrackerApp() {
  const [phoneNumber, setPhoneNumber] = useState('');
  const [password, setPassword] = useState('');
  const [targetPhone, setTargetPhone] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [token, setToken] = useState('');
  const [userLocation, setUserLocation] = useState(null);
  const [targetLocation, setTargetLocation] = useState(null);
  const [isSharing, setIsSharing] = useState(false);

  // Login function
  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phoneNumber, password }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setToken(data.token);
        setIsLoggedIn(true);
        startLocationTracking();
      } else {
        Alert.alert('Error', data.error);
      }
    } catch (error) {
      Alert.alert('Error', 'Login failed');
    }
  };

  // Start tracking user's location
  const startLocationTracking = async () => {
    const { status } = await Location.requestForegroundPermissionsAsync();
    
    if (status !== 'granted') {
      Alert.alert('Permission denied', 'Location permission is required');
      return;
    }

    // Get initial location
    const location = await Location.getCurrentPositionAsync({});
    setUserLocation(location.coords);
    await updateLocationOnServer(location.coords);

    // Update location periodically
    setInterval(async () => {
      const newLocation = await Location.getCurrentPositionAsync({});
      setUserLocation(newLocation.coords);
      await updateLocationOnServer(newLocation.coords);
    }, 30000); // Update every 30 seconds
  };

  // Update location on server
  const updateLocationOnServer = async (coords) => {
    try {
      await fetch(`${API_BASE_URL}/location/update`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          latitude: coords.latitude,
          longitude: coords.longitude
        }),
      });
    } catch (error) {
      console.error('Failed to update location:', error);
    }
  };

  // Start tracking another user
  const startTracking = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/tracking/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ targetPhoneNumber: targetPhone }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        Alert.alert('Success', 'Tracking request sent');
        // Start polling for target location
        setInterval(fetchTargetLocation, 15000);
      } else {
        Alert.alert('Error', data.error);
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to start tracking');
    }
  };

  // Fetch target location
  const fetchTargetLocation = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/location/${targetPhone}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        },
      });
      
      if (response.ok) {
        const data = await response.json();
        setTargetLocation(data.location);
      }
    } catch (error) {
      console.error('Failed to fetch target location:', error);
    }
  };

  // Toggle location sharing
  const toggleSharing = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/sharing/toggle`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ isSharing: !isSharing }),
      });
      
      if (response.ok) {
        const data = await response.json();
        setIsSharing(data.isSharing);
        Alert.alert('Success', data.message);
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to toggle sharing');
    }
  };

  if (!isLoggedIn) {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>Location Tracker</Text>
        <TextInput
          style={styles.input}
          placeholder="Phone Number"
          value={phoneNumber}
          onChangeText={setPhoneNumber}
          keyboardType="phone-pad"
        />
        <TextInput
          style={styles.input}
          placeholder="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
        />
        <Button title="Login" onPress={handleLogin} />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Location Tracker</Text>
      
      <View style={styles.controls}>
        <TextInput
          style={styles.input}
          placeholder="Target Phone Number"
          value={targetPhone}
          onChangeText={setTargetPhone}
        />
        <Button title="Start Tracking" onPress={startTracking} />
        
        <View style={styles.sharingToggle}>
          <Text>Location Sharing: {isSharing ? 'ON' : 'OFF'}</Text>
          <Button 
            title={isSharing ? "Disable Sharing" : "Enable Sharing"} 
            onPress={toggleSharing} 
          />
        </View>
      </View>

      {userLocation && (
        <MapView
          style={styles.map}
          initialRegion={{
            latitude: userLocation.latitude,
            longitude: userLocation.longitude,
            latitudeDelta: 0.0922,
            longitudeDelta: 0.0421,
          }}
        >
          <Marker
            coordinate={{
              latitude: userLocation.latitude,
              longitude: userLocation.longitude,
            }}
            title="Your Location"
          />
          
          {targetLocation && (
            <Marker
              coordinate={{
                latitude: targetLocation.latitude,
                longitude: targetLocation.longitude,
              }}
              title="Target Location"
              pinColor="red"
            />
          )}
        </MapView>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    paddingTop: 50,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 10,
    borderRadius: 5,
  },
  controls: {
    marginBottom: 20,
  },
  sharingToggle: {
    marginTop: 10,
    padding: 10,
    backgroundColor: '#f0f0f0',
    borderRadius: 5,
  },
  map: {
    flex: 1,
    marginTop: 10,
  },
});
{
  "name": "location-tracker",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.0.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "twilio": "^4.0.0",
    "axios": "^1.4.0"
  }
}
MONGODB_URI=mongodb://localhost:27017/locationtracker
JWT_SECRET=your-jwt-secret-key
TWILIO_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=your-twilio-phone-number
