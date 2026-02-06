# API Examples

Code examples for the Media Center Arti Marziali API in curl, Python, and JavaScript.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Videos](#videos)
3. [Streaming](#streaming)
4. [Ads](#ads)
5. [Payments](#payments)
6. [Live Streaming](#live-streaming)
7. [Blockchain](#blockchain)
8. [Communication](#communication)
9. [Error Handling](#error-handling)

---

## Authentication

### Register User

**curl**
```bash
curl -X POST "https://api.example.com/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "username": "martial_artist",
    "full_name": "John Doe"
  }'
```

**Python**
```python
import requests

BASE_URL = "https://api.example.com/api/v1"

response = requests.post(
    f"{BASE_URL}/auth/register",
    json={
        "email": "user@example.com",
        "password": "SecurePass123!",
        "username": "martial_artist",
        "full_name": "John Doe"
    }
)

if response.status_code == 201:
    user = response.json()
    print(f"User created: {user['id']}")
else:
    print(f"Error: {response.json()['detail']}")
```

**JavaScript**
```javascript
const BASE_URL = "https://api.example.com/api/v1";

async function registerUser() {
  const response = await fetch(`${BASE_URL}/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: "user@example.com",
      password: "SecurePass123!",
      username: "martial_artist",
      full_name: "John Doe",
    }),
  });

  if (response.ok) {
    const user = await response.json();
    console.log("User created:", user.id);
  } else {
    const error = await response.json();
    console.error("Error:", error.detail);
  }
}
```

---

### Login

**curl**
```bash
curl -X POST "https://api.example.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Python**
```python
import requests

BASE_URL = "https://api.example.com/api/v1"

# Login
response = requests.post(
    f"{BASE_URL}/auth/login",
    json={
        "email": "user@example.com",
        "password": "SecurePass123!"
    }
)

if response.status_code == 200:
    tokens = response.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Store tokens for later use
    headers = {"Authorization": f"Bearer {access_token}"}
    print("Login successful!")
else:
    print(f"Login failed: {response.json()['detail']}")
```

**JavaScript**
```javascript
const BASE_URL = "https://api.example.com/api/v1";

async function login(email, password) {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });

  if (response.ok) {
    const tokens = await response.json();
    // Store tokens
    localStorage.setItem("accessToken", tokens.access_token);
    localStorage.setItem("refreshToken", tokens.refresh_token);
    return tokens;
  } else {
    throw new Error((await response.json()).detail);
  }
}

// Usage
login("user@example.com", "SecurePass123!")
  .then((tokens) => console.log("Logged in, expires in:", tokens.expires_in))
  .catch((err) => console.error("Login failed:", err));
```

---

### Refresh Token

**curl**
```bash
curl -X POST "https://api.example.com/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Python**
```python
import requests

def refresh_access_token(refresh_token):
    response = requests.post(
        f"{BASE_URL}/auth/refresh",
        json={"refresh_token": refresh_token}
    )

    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        raise Exception("Token refresh failed")

# Auto-refresh wrapper
class APIClient:
    def __init__(self, base_url, access_token, refresh_token):
        self.base_url = base_url
        self.access_token = access_token
        self.refresh_token = refresh_token

    def _get_headers(self):
        return {"Authorization": f"Bearer {self.access_token}"}

    def request(self, method, endpoint, **kwargs):
        response = requests.request(
            method,
            f"{self.base_url}{endpoint}",
            headers=self._get_headers(),
            **kwargs
        )

        # Auto-refresh on 401
        if response.status_code == 401:
            self.access_token = refresh_access_token(self.refresh_token)
            response = requests.request(
                method,
                f"{self.base_url}{endpoint}",
                headers=self._get_headers(),
                **kwargs
            )

        return response
```

**JavaScript**
```javascript
class APIClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  async fetch(endpoint, options = {}) {
    const accessToken = localStorage.getItem("accessToken");

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    // Auto-refresh on 401
    if (response.status === 401) {
      await this.refreshToken();
      return this.fetch(endpoint, options);
    }

    return response;
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem("refreshToken");

    const response = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem("accessToken", data.access_token);
    } else {
      // Redirect to login
      window.location.href = "/login";
    }
  }
}

const api = new APIClient("https://api.example.com/api/v1");
```

---

## Videos

### List Videos with Filters

**curl**
```bash
# Basic listing
curl "https://api.example.com/api/v1/videos?limit=20"

# With filters
curl "https://api.example.com/api/v1/videos?category=kata&difficulty=beginner&sort_by=view_count&sort_order=desc"

# Search
curl "https://api.example.com/api/v1/videos/search?q=karate"
```

**Python**
```python
import requests

def list_videos(category=None, difficulty=None, search=None, limit=20, skip=0):
    params = {"limit": limit, "skip": skip}

    if category:
        params["category"] = category
    if difficulty:
        params["difficulty"] = difficulty
    if search:
        params["search"] = search

    response = requests.get(f"{BASE_URL}/videos", params=params)

    if response.status_code == 200:
        data = response.json()
        return {
            "videos": data["videos"],
            "total": data["total"],
            "has_more": (skip + len(data["videos"])) < data["total"]
        }

    return None

# Usage
karate_videos = list_videos(category="kata", difficulty="beginner")
print(f"Found {karate_videos['total']} videos")

for video in karate_videos["videos"]:
    print(f"- {video['title']} ({video['view_count']} views)")
```

**JavaScript**
```javascript
async function listVideos(options = {}) {
  const params = new URLSearchParams({
    limit: options.limit || 20,
    skip: options.skip || 0,
    ...(options.category && { category: options.category }),
    ...(options.difficulty && { difficulty: options.difficulty }),
    ...(options.search && { search: options.search }),
    sort_by: options.sortBy || "created_at",
    sort_order: options.sortOrder || "desc",
  });

  const response = await api.fetch(`/videos?${params}`);

  if (response.ok) {
    return response.json();
  }

  throw new Error("Failed to fetch videos");
}

// Usage
listVideos({ category: "kata", difficulty: "beginner" })
  .then((data) => {
    console.log(`Found ${data.total} videos`);
    data.videos.forEach((v) => console.log(`- ${v.title}`));
  });

// Infinite scroll example
class VideoLoader {
  constructor() {
    this.videos = [];
    this.skip = 0;
    this.hasMore = true;
  }

  async loadMore() {
    if (!this.hasMore) return;

    const data = await listVideos({ skip: this.skip, limit: 20 });
    this.videos.push(...data.videos);
    this.skip += data.videos.length;
    this.hasMore = this.skip < data.total;

    return data.videos;
  }
}
```

---

## Streaming

### Get Streaming URL

**curl**
```bash
curl "https://api.example.com/api/v1/videos/550e8400-e29b-41d4-a716-446655440000/stream?quality=1080p" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Python**
```python
import requests

def get_streaming_url(video_id, quality="auto", headers=None):
    """Get HLS streaming URL for a video."""
    response = requests.get(
        f"{BASE_URL}/videos/{video_id}/stream",
        params={"quality": quality},
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        return {
            "url": data["streaming_url"],
            "token": data["token"],
            "expires_in": data["expires_in"],
            "quality": data["quality"],
            "available_qualities": data["available_qualities"],
            "subtitles": data.get("subtitles", {})
        }
    elif response.status_code == 403:
        # User needs to upgrade or watch ads
        raise PermissionError(response.json()["detail"])
    else:
        raise Exception(f"Failed to get streaming URL: {response.status_code}")

# Usage with video.js
def get_videojs_config(video_id, headers):
    stream = get_streaming_url(video_id, headers=headers)

    return {
        "sources": [{
            "src": stream["url"],
            "type": "application/x-mpegURL"
        }],
        "textTracks": [
            {"src": url, "srclang": lang, "label": lang.upper()}
            for lang, url in stream.get("subtitles", {}).items()
        ]
    }
```

**JavaScript**
```javascript
async function getStreamingUrl(videoId, quality = "auto") {
  const response = await api.fetch(`/videos/${videoId}/stream?quality=${quality}`);

  if (response.ok) {
    return response.json();
  }

  if (response.status === 403) {
    const error = await response.json();
    // Handle upgrade/ads flow
    throw new Error(error.detail);
  }

  throw new Error("Failed to get streaming URL");
}

// HLS.js integration
async function playVideo(videoId, videoElement) {
  const stream = await getStreamingUrl(videoId, "1080p");

  if (Hls.isSupported()) {
    const hls = new Hls();
    hls.loadSource(stream.streaming_url);
    hls.attachMedia(videoElement);

    hls.on(Hls.Events.MANIFEST_PARSED, () => {
      videoElement.play();
    });

    // Handle quality switching
    hls.on(Hls.Events.LEVEL_LOADED, (event, data) => {
      console.log("Quality:", data.level);
    });

    return hls;
  } else if (videoElement.canPlayType("application/vnd.apple.mpegurl")) {
    // Native HLS support (Safari)
    videoElement.src = stream.streaming_url;
    videoElement.play();
  }
}

// Track viewing progress
async function trackProgress(videoId, positionSeconds) {
  await api.fetch(`/videos/${videoId}/progress`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ position_seconds: positionSeconds }),
  });
}

// Periodic progress update
let progressInterval;

function startProgressTracking(videoId, videoElement) {
  progressInterval = setInterval(() => {
    if (!videoElement.paused) {
      trackProgress(videoId, Math.floor(videoElement.currentTime));
    }
  }, 30000); // Every 30 seconds
}

function stopProgressTracking() {
  clearInterval(progressInterval);
}
```

---

## Ads

### Start Ads Batch Session

**curl**
```bash
curl -X POST "https://api.example.com/api/v1/ads/sessions/start" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_type": "3_video"}'
```

**Python**
```python
import requests

class AdsSession:
    """Manage ads batch session."""

    def __init__(self, base_url, headers):
        self.base_url = base_url
        self.headers = headers
        self.session = None

    def start(self, batch_type="3_video"):
        """Start ads batch session."""
        response = requests.post(
            f"{self.base_url}/ads/sessions/start",
            json={"batch_type": batch_type},
            headers=self.headers
        )

        if response.status_code == 200:
            self.session = response.json()
            return self.session

        raise Exception(response.json()["detail"])

    def record_view(self, ad_id, duration):
        """Record ad view."""
        if not self.session:
            raise Exception("No active session")

        response = requests.post(
            f"{self.base_url}/ads/sessions/{self.session['session_id']}/view",
            params={"ad_id": ad_id, "duration": duration},
            headers=self.headers
        )

        return response.json()

    def complete(self):
        """Complete session and unlock videos."""
        if not self.session:
            raise Exception("No active session")

        response = requests.post(
            f"{self.base_url}/ads/sessions/{self.session['session_id']}/complete",
            headers=self.headers
        )

        if response.status_code == 200:
            self.session = None
            return True

        return False

# Usage
ads = AdsSession(BASE_URL, headers)
session = ads.start("5_video")
print(f"Need to watch {session['ads_required_duration']}s of ads")

# After watching ads
ads.record_view("ad-uuid-1", 30)
ads.record_view("ad-uuid-2", 30)

# Complete and unlock
if ads.complete():
    print("Videos unlocked!")
```

**JavaScript**
```javascript
class AdsManager {
  constructor(api) {
    this.api = api;
    this.session = null;
  }

  async startSession(batchType = "3_video") {
    const response = await this.api.fetch("/ads/sessions/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batch_type: batchType }),
    });

    if (response.ok) {
      this.session = await response.json();
      return this.session;
    }

    throw new Error((await response.json()).detail);
  }

  async recordView(adId, duration) {
    if (!this.session) throw new Error("No active session");

    const response = await this.api.fetch(
      `/ads/sessions/${this.session.session_id}/view?ad_id=${adId}&duration=${duration}`,
      { method: "POST" }
    );

    return response.json();
  }

  async complete() {
    if (!this.session) throw new Error("No active session");

    const response = await this.api.fetch(
      `/ads/sessions/${this.session.session_id}/complete`,
      { method: "POST" }
    );

    if (response.ok) {
      this.session = null;
      return true;
    }

    return false;
  }
}

// Pause ad overlay
async function handleVideoPause(videoId) {
  const response = await api.fetch(`/ads/pause-ad?video_id=${videoId}`);

  if (response.ok) {
    const overlay = await response.json();

    if (overlay.show_overlay) {
      showPauseAdOverlay(overlay);

      // Record impression
      await api.fetch("/ads/pause-ad/impression", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          impression_id: overlay.impression_id,
          video_id: videoId,
        }),
      });
    }
  }
}
```

---

## Payments

### Purchase Stelline

**curl**
```bash
curl -X POST "https://api.example.com/api/v1/payments/stelline/purchase" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package": "medium"}'
```

**Python**
```python
import stripe

def purchase_stelline(package, headers):
    """Create stelline purchase intent."""
    response = requests.post(
        f"{BASE_URL}/payments/stelline/purchase",
        json={"package": package},
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        return {
            "client_secret": data["client_secret"],
            "amount": data["amount_eur"],
            "stelline": data["stelline_amount"]
        }

    raise Exception(response.json()["detail"])

def confirm_stelline_purchase(payment_intent_id, headers):
    """Confirm purchase after Stripe payment."""
    response = requests.post(
        f"{BASE_URL}/payments/stelline/confirm",
        json={"payment_intent_id": payment_intent_id},
        headers=headers
    )

    if response.status_code == 200:
        return response.json()

    raise Exception(response.json()["detail"])

# Usage
purchase = purchase_stelline("medium", headers)
print(f"Pay {purchase['amount']} EUR for {purchase['stelline']} stelline")

# Use Stripe.js on frontend to confirm payment with client_secret
# After Stripe confirms payment:
result = confirm_stelline_purchase(purchase["payment_intent_id"], headers)
print(f"New balance: {result['new_balance']} stelline")
```

**JavaScript**
```javascript
// Stripe Elements integration
async function purchaseStelline(package) {
  // 1. Create payment intent
  const response = await api.fetch("/payments/stelline/purchase", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package }),
  });

  if (!response.ok) throw new Error((await response.json()).detail);

  const { client_secret, amount_eur, stelline_amount } = await response.json();

  // 2. Confirm with Stripe
  const stripe = Stripe("pk_test_xxx");
  const { error, paymentIntent } = await stripe.confirmCardPayment(
    client_secret,
    {
      payment_method: {
        card: cardElement, // Stripe Elements card
        billing_details: { name: "John Doe" },
      },
    }
  );

  if (error) {
    throw new Error(error.message);
  }

  // 3. Confirm with backend
  const confirmResponse = await api.fetch("/payments/stelline/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ payment_intent_id: paymentIntent.id }),
  });

  return confirmResponse.json();
}

// Subscription creation
async function createSubscription(tier) {
  const response = await api.fetch("/payments/subscription/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tier }),
  });

  if (!response.ok) throw new Error((await response.json()).detail);

  const { client_secret, amount_eur } = await response.json();

  // Confirm subscription payment with Stripe
  const stripe = Stripe("pk_test_xxx");
  const { error } = await stripe.confirmCardPayment(client_secret, {
    payment_method: { card: cardElement },
  });

  if (error) throw new Error(error.message);

  return { success: true, amount: amount_eur };
}
```

---

## Live Streaming

### Create and Manage Live Event

**curl**
```bash
# Create event
curl -X POST "https://api.example.com/api/v1/live/events" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Live Seminar: Advanced Kata",
    "scheduled_start": "2026-01-20T18:00:00Z",
    "tier_required": "premium"
  }'

# Start event
curl -X POST "https://api.example.com/api/v1/live/events/EVENT_ID/start" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

**Python**
```python
import websockets
import asyncio
import json

async def watch_live_event(event_id):
    """Connect to live event WebSocket."""
    uri = f"wss://api.example.com/api/v1/live/events/{event_id}/ws"

    async with websockets.connect(uri) as ws:
        while True:
            message = await ws.recv()
            data = json.loads(message)

            if data["type"] == "viewer_count":
                print(f"Viewers: {data['count']}")
            elif data["type"] == "ping":
                await ws.send(json.dumps({"type": "pong"}))

# Usage
asyncio.run(watch_live_event("event-uuid"))
```

**JavaScript**
```javascript
class LiveEventViewer {
  constructor(eventId) {
    this.eventId = eventId;
    this.ws = null;
    this.onViewerCountChange = null;
  }

  connect() {
    const accessToken = localStorage.getItem("accessToken");
    this.ws = new WebSocket(
      `wss://api.example.com/api/v1/live/events/${this.eventId}/ws?token=${accessToken}`
    );

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "viewer_count" && this.onViewerCountChange) {
        this.onViewerCountChange(data.count);
      }
    };

    this.ws.onclose = () => {
      // Reconnect after 3 seconds
      setTimeout(() => this.connect(), 3000);
    };
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Usage
const viewer = new LiveEventViewer("event-uuid");
viewer.onViewerCountChange = (count) => {
  document.getElementById("viewer-count").textContent = count;
};
viewer.connect();
```

---

## Blockchain

### Create and Publish Batch

**curl**
```bash
# Create weekly batch
curl -X POST "https://api.example.com/api/v1/blockchain/batches/create?week_offset=0" \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Get batch status
curl "https://api.example.com/api/v1/blockchain/batches/BATCH_ID"

# Publish to blockchain
curl -X POST "https://api.example.com/api/v1/blockchain/batches/BATCH_ID/publish" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

**Python**
```python
def create_and_publish_batch(headers, week_offset=0):
    """Create and publish blockchain batch."""

    # 1. Create batch
    response = requests.post(
        f"{BASE_URL}/blockchain/batches/create",
        params={"week_offset": week_offset},
        headers=headers
    )

    if response.status_code != 200:
        raise Exception("Failed to create batch")

    batch_id = response.json()["batch_id"]
    print(f"Batch created: {batch_id}")

    # 2. Wait for validations (in production)
    # Nodes validate and call /validate endpoint

    # 3. Publish to blockchain
    response = requests.post(
        f"{BASE_URL}/blockchain/batches/{batch_id}/publish",
        headers=headers
    )

    if response.status_code == 200:
        result = response.json()
        print(f"Published! TX: {result['blockchain_tx_hash']}")
        print(f"Explorer: {result['explorer_url']}")
        return result

    raise Exception("Failed to publish batch")

# Usage
result = create_and_publish_batch(admin_headers)
```

---

## Communication

### Send Messages and Correction Requests

**Python**
```python
def send_message(to_user_id, content, headers):
    """Send message to another user."""
    response = requests.post(
        f"{BASE_URL}/communication/messages",
        json={
            "to_user_id": to_user_id,
            "content": content
        },
        headers=headers
    )

    return response.json()

def create_correction_request(maestro_id, video_url, notes, headers):
    """Request video correction from maestro."""
    response = requests.post(
        f"{BASE_URL}/communication/corrections",
        json={
            "maestro_id": maestro_id,
            "video_url": video_url,
            "notes": notes
        },
        headers=headers
    )

    return response.json()

# Real-time chat with WebSocket
import websockets
import asyncio
import json

async def chat_client(user_id):
    uri = f"wss://api.example.com/api/v1/communication/ws/chat/{user_id}"

    async with websockets.connect(uri) as ws:
        # Receive messages
        async def receiver():
            async for message in ws:
                data = json.loads(message)
                if data["type"] == "new_message":
                    print(f"{data['from_user_id']}: {data['content']}")

        # Send messages
        async def sender():
            while True:
                content = await asyncio.get_event_loop().run_in_executor(
                    None, input, "You: "
                )
                await ws.send(json.dumps({
                    "to_user_id": "recipient-uuid",
                    "content": content
                }))

        await asyncio.gather(receiver(), sender())
```

---

## Error Handling

### Comprehensive Error Handler

**Python**
```python
class APIError(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail

def handle_response(response):
    """Handle API response and raise appropriate errors."""
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 201:
        return response.json()
    elif response.status_code == 204:
        return None
    elif response.status_code == 400:
        raise APIError(400, response.json().get("detail", "Bad request"))
    elif response.status_code == 401:
        raise APIError(401, "Authentication required")
    elif response.status_code == 403:
        raise APIError(403, response.json().get("detail", "Permission denied"))
    elif response.status_code == 404:
        raise APIError(404, response.json().get("detail", "Not found"))
    elif response.status_code == 422:
        errors = response.json().get("detail", [])
        raise APIError(422, f"Validation error: {errors}")
    else:
        raise APIError(response.status_code, "Unknown error")

# Usage
try:
    response = requests.get(f"{BASE_URL}/videos/{video_id}", headers=headers)
    video = handle_response(response)
except APIError as e:
    if e.status_code == 401:
        # Redirect to login
        pass
    elif e.status_code == 403:
        # Show upgrade prompt
        pass
    else:
        print(f"Error: {e.detail}")
```

**JavaScript**
```javascript
class APIError extends Error {
  constructor(statusCode, detail) {
    super(detail);
    this.statusCode = statusCode;
  }
}

async function handleResponse(response) {
  if (response.ok) {
    if (response.status === 204) return null;
    return response.json();
  }

  const error = await response.json().catch(() => ({}));

  switch (response.status) {
    case 400:
      throw new APIError(400, error.detail || "Bad request");
    case 401:
      // Redirect to login
      window.location.href = "/login";
      throw new APIError(401, "Authentication required");
    case 403:
      throw new APIError(403, error.detail || "Permission denied");
    case 404:
      throw new APIError(404, error.detail || "Not found");
    case 422:
      throw new APIError(422, `Validation error: ${JSON.stringify(error.detail)}`);
    default:
      throw new APIError(response.status, "Unknown error");
  }
}

// Usage with React
function useAPI() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const request = async (endpoint, options) => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.fetch(endpoint, options);
      return await handleResponse(response);
    } catch (e) {
      setError(e);
      throw e;
    } finally {
      setLoading(false);
    }
  };

  return { request, loading, error };
}
```

---

*Examples last updated: 2026-01-17*
