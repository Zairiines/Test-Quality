import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl = 'http://localhost:8000/server/users'; // URL de base pour l'API
  private tokenKey = 'authToken'; // Clé pour stocker le token dans le localStorage
  private userKey = 'currentUser'; // Clé pour stocker les informations de l'utilisateur dans le localStorage

  constructor(private http: HttpClient) {}

  // Récupérer le token stocké dans le localStorage
  getToken(): string {
    const token = localStorage.getItem(this.tokenKey);
    console.log('Token récupéré:', token);
    return token || '';
  }

  // Stocker le token et les informations de l'utilisateur dans le localStorage
  setSession(authResult: any): void {
    localStorage.setItem(this.tokenKey, authResult.token);
    localStorage.setItem(this.userKey, JSON.stringify(authResult.user));
  }

  // Connexion de l'utilisateur
  login(username: string, password: string): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/login`, { username, password }).pipe(
      tap(response => {
        if (response.token && response.user) {
          this.setSession(response); // Stocker le token et l'utilisateur en cas de succès
        }
      }),
      catchError(this.handleError)
    );
  }

  // Inscription de l'utilisateur
  register(user: { username: string; email: string; password: string; role: string }): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/register`, user).pipe(
      catchError(this.handleError)
    );
  }

  // Gestion des erreurs
  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'Une erreur est survenue lors de la connexion.';
    if (error.error instanceof ErrorEvent) {
      // Erreur côté client
      errorMessage = `Erreur : ${error.error.message}`;
    } else {
      // Erreur côté serveur
      switch (error.status) {
        case 400:
          errorMessage = 'Requête incorrecte. Veuillez vérifier les informations.';
          break;
        case 401:
          errorMessage = 'Identifiants invalides. Veuillez vérifier votre nom d\'utilisateur et votre mot de passe.';
          break;
        case 404:
          errorMessage = 'Utilisateur non trouvé. Veuillez vérifier votre nom d\'utilisateur.';
          break;
        case 500:
          errorMessage = 'Erreur serveur. Veuillez réessayer plus tard.';
          break;
        default:
          errorMessage = `Code d'erreur : ${error.status}\nMessage : ${error.message}`;
          break;
      }
    }
    return throwError(() => new Error(errorMessage));
  }
}
