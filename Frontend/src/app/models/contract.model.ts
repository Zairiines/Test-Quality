import { FileDocument } from '../models/document.model'; // Assurez-vous que ce modèle est défini correctement

export interface Contract {
  contractId?: number;
  dateDebut: string;
  dateFin: string;
  entrepriseName: string;
  userId: number;
  title?: string;
  description?: string;
  documents?: FileDocument[];  // Changement pour utiliser FileDocument
}

export interface ContractDTO {
  contractId?: number;
  dateDebut: string;
  dateFin: string;
  entrepriseName: string;
  userId: number;
  title?: string;
  description?: string;
  documents?: FileDocument[];  // Changement pour utiliser FileDocument
}
