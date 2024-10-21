import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { User } from '../models/user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = 'http://localhost:8000/server/users';

  constructor(
    private http: HttpClient,
    private authService: AuthService
  ) { }

  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(this.apiUrl).pipe(
      catchError(this.handleError)
    );
  }

  getUser(username: string): Observable<User> {
    return this.http.get<User>(`${this.apiUrl}/${username}`).pipe(
      catchError(this.handleError)
    );
  }

  registerUser(user: User): Observable<User> {
    return this.http.post<User>(`${this.apiUrl}/register`, user).pipe(
      catchError(this.handleError)
    );
  }

  deleteUser(id: number): Observable<void> {
    const token = this.authService.getToken();
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    return this.http.delete<void>(`${this.apiUrl}/${id}`, { headers }).pipe(
      catchError(this.handleError)
    );
  }

  updateUser(id: number, user: Partial<User>): Observable<void> {
    const token = this.authService.getToken();
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    });
    return this.http.put<void>(`${this.apiUrl}/update/${id}`, user, { headers }).pipe(
      catchError(this.handleError)
    );
  }

  getCurrentUser(): Observable<User> {
    const token = this.authService.getToken();
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    return this.http.get<User>(`${this.apiUrl}/current`, { headers }).pipe(
      catchError(this.handleError)
    );
  }

  // Nouvelle méthode pour ajouter un utilisateur
  addUser(user: User): Observable<User> {
    return this.http.post<User>(`${this.apiUrl}/register`, user).pipe(
      catchError(this.handleError)
    );
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'Une erreur est survenue lors de la requête.';
    if (error.error instanceof ErrorEvent) {
      errorMessage = `Erreur : ${error.error.message}`;
    } else {
      switch (error.status) {
        case 400:
          errorMessage = 'Requête incorrecte. Veuillez vérifier les informations.';
          break;
        case 401:
          errorMessage = 'Non autorisé. Veuillez vérifier vos identifiants.';
          break;
        case 403:
          errorMessage = 'Interdit. Vous n\'avez pas les permissions nécessaires.';
          break;
        case 404:
          errorMessage = 'Ressource non trouvée. Veuillez vérifier l\'URL.';
          break;
        case 500:
          errorMessage = 'Erreur interne du serveur. Veuillez réessayer plus tard.';
          break;
        default:
          errorMessage = `Code d'erreur : ${error.status}\nMessage : ${error.message}`;
          break;
      }
    }
    return throwError(() => new Error(errorMessage));
  }
}
