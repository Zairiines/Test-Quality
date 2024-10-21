import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { FileDocument } from '../models/document.model'; // Assurez-vous que ce modèle est défini correctement

@Injectable({
  providedIn: 'root'
})
export class DocumentService {
  private baseUrl = 'http://localhost:8000/api/documents';

  constructor(private http: HttpClient) { }

  // Méthode pour uploader un document
  uploadDocument(file: File, title: string, description: string, type: string, contractId: number): Observable<string> {
    const formData: FormData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    formData.append('description', description);
    formData.append('type', type);
    formData.append('contractId', contractId.toString());

    return this.http.post<string>(`${this.baseUrl}/upload`, formData, { responseType: 'text' as 'json' })
      .pipe(
        catchError(this.handleError)
      );
  }

  // Méthode pour télécharger un document par son ID
  downloadDocument(documentId: number): Observable<Blob> {
    return this.http.get<Blob>(`${this.baseUrl}/download/${documentId}`, { responseType: 'blob' as 'json' })
      .pipe(
        catchError(this.handleError)
      );
  }

  // Méthode pour obtenir la liste des documents
  getDocuments(): Observable<FileDocument[]> {  // Utilisation de FileDocument
    return this.http.get<FileDocument[]>(this.baseUrl)
      .pipe(
        catchError(this.handleError)
      );
  }

  // Nouvelle méthode pour obtenir les documents associés à un contrat spécifique
  getDocumentsByContractId(contractId: number): Observable<FileDocument[]> {
    return this.http.get<FileDocument[]>(`${this.baseUrl}/contract/${contractId}`)
      .pipe(
        catchError(this.handleError)
      );
  }

  private handleError(error: any): Observable<never> {
    console.error('An error occurred:', error);
    return throwError(error);
  }
}
