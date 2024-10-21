import { Injectable } from '@angular/core'; // Ajout de l'importation manquante pour Injectable
import { HttpClient } from '@angular/common/http'; // Ajout de l'importation manquante pour HttpClient
import { Observable } from 'rxjs'; // Ajout de l'importation manquante pour Observable

@Injectable({
  providedIn: 'root'
})
export class NotificationService {

  private apiUrl = 'http://localhost:8000//api/contracts'; // URL de base de l'API

  constructor(private http: HttpClient) {}

  // Méthode pour déclencher manuellement les notifications des contrats qui expirent
  triggerContractNotification(): Observable<void> {
    return this.http.post<void>(`${this.apiUrl}/testNotifyUsersOfEndingContracts`, {});
  }
}
