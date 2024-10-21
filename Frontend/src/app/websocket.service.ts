import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class WebsocketService {
  private socket: WebSocket | null = null; // Initialisation avec `null`
  private messageSubject: Subject<any> = new Subject<any>();

  constructor() { }

  connect(url: string): void {
    this.socket = new WebSocket(url);

    this.socket.onmessage = (event) => {
      this.messageSubject.next(event.data);
    };

    this.socket.onerror = (event) => {
      console.error("WebSocket error observed:", event);
    };

    this.socket.onclose = (event) => {
      console.log("WebSocket connection closed:", event);
      this.socket = null; // Réinitialisation du socket lorsqu'il est fermé
    };
  }

  sendMessage(message: string): void {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(message);
    } else {
      console.error("WebSocket connection is not open");
    }
  }

  onMessage(): Observable<any> {
    return this.messageSubject.asObservable();
  }

  close(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null; // Réinitialisation du socket lors de la fermeture manuelle
    }
  }
}
