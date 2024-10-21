import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ContractDTO } from '../models/contract.model';  // Assurez-vous que le chemin est correct

@Injectable({
  providedIn: 'root'
})
export class ContractService {
  private baseUrl = 'http://localhost:8000/api/contracts';

  constructor(private http: HttpClient) { }

  getAllContracts(): Observable<ContractDTO[]> {
    return this.http.get<ContractDTO[]>(`${this.baseUrl}/getAllContracts`);
  }

  getContractById(contractId: number): Observable<ContractDTO> {
    return this.http.get<ContractDTO>(`${this.baseUrl}/getContract/${contractId}`);
  }

  createContract(contract: ContractDTO): Observable<ContractDTO> {
    return this.http.post<ContractDTO>(`${this.baseUrl}/createContract`, contract);
  }

  updateContract(contractId: number, contract: ContractDTO): Observable<ContractDTO> {
    return this.http.put<ContractDTO>(`${this.baseUrl}/updateContract/${contractId}`, contract);
  }

  deleteContract(contractId: number): Observable<string> {
    return this.http.delete<string>(`${this.baseUrl}/deleteContract/${contractId}`);
  }

  // Nouvelle méthode ajoutée pour récupérer un contrat par titre
  getContractByName(title: string): Observable<ContractDTO> {
    return this.http.get<ContractDTO>(`${this.baseUrl}/getContractByName/${title}`);
  }
}
