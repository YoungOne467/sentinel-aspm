class CollabService {
  private static instance: CollabService;
  private ws?: WebSocket;
  private callbacks: ((event: MessageEvent) => void)[] = [];
  private reconnectDelay = 1000;

  private constructor() {
    this.connect();
  }

  public static getInstance(): CollabService {
    if (!CollabService.instance) {
      CollabService.instance = new CollabService();
    }
    return CollabService.instance;
  }

  private getUrl(): string {
    const host = window.location.host;
    return `ws://${host}/ws/collab`;
  }

  private connect() {
    this.ws = new WebSocket(this.getUrl());
    this.ws.onopen = () => {
      console.log('Collab WebSocket connected');
    };
    this.ws.onmessage = (msg) => {
      this.callbacks.forEach((cb) => cb(msg));
    };
    this.ws.onclose = () => {
      console.warn('Collab WebSocket closed, reconnecting...');
      setTimeout(() => this.connect(), this.reconnectDelay);
    };
    this.ws.onerror = (err) => {
      console.error('Collab WebSocket error', err);
      this.ws?.close();
    };
  }

  public send(event: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(event));
    } else {
      console.warn('Collab WebSocket not open, cannot send');
    }
  }

  public onMessage(callback: (event: MessageEvent) => void) {
    this.callbacks.push(callback);
    // Return unsubscribe function
    return () => {
      this.callbacks = this.callbacks.filter((cb) => cb !== callback);
    };
  }
}

export const collabService = CollabService.getInstance();
