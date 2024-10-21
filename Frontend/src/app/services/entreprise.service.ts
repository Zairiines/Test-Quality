import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Entreprise } from 'src/app/models/entreprise.model';

@Injectable({
  providedIn: 'root'
})
export class EntrepriseService {
  private baseUrl = 'http://localhost:8000/server/entreprises';

  constructor(private http: HttpClient) { }

  getAllEntreprises(): Observable<Entreprise[]> {
    return this.http.get<Entreprise[]>(`${this.baseUrl}`);
  }

  updateEntreprise(id: number, entreprise: Entreprise): Observable<Entreprise> {
    return this.http.put<Entreprise>(`${this.baseUrl}/update/${id}`, entreprise);
  }
  
  deleteEntreprise(id: number): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/${id}`);
  }

  addEntreprise(entreprise: Entreprise): Observable<Entreprise> {
    return this.http.post<Entreprise>(`${this.baseUrl}/addEntreprise`, entreprise);
  }

  // Nouvelle méthode pour récupérer une entreprise par son nom
  getEntrepriseByName(name: string): Observable<Entreprise> {
    return this.http.get<Entreprise>(`${this.baseUrl}/${name}`);
  }
}
