import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { Router, ActivatedRoute } from '@angular/router';
import { DocumentService } from '../services/document.service';
import { FileDocument } from '../models/document.model';
import { UploadDocumentDialogComponent } from '../upload-document-dialog/upload-document-dialog.component';

@Component({
  selector: 'app-document-manager',
  templateUrl: './document-manager.component.html',
  styleUrls: ['./document-manager.component.scss']
})
export class DocumentManagerComponent implements OnInit {
  documents: FileDocument[] = [];
  contractId: number | null = null;

  constructor(
    private documentService: DocumentService,
    private dialog: MatDialog,
    private router: Router,
    private route: ActivatedRoute
  ) { }

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      const id = params.get('contractId');
      this.contractId = id ? +id : null; // Convertir en nombre ou définir null
      if (this.contractId !== null && !isNaN(this.contractId)) {
        this.loadDocuments();
      } else {
        console.error('ID de contrat invalide ou manquant.');
      }
    });
  }

  // Charge la liste des documents depuis le serveur pour un contractId spécifique
  loadDocuments(): void {
    if (this.contractId !== null) {
      this.documentService.getDocumentsByContractId(this.contractId).subscribe({
        next: (data) => {
          this.documents = data;
        },
        error: (err) => {
          console.error('Erreur lors du chargement des documents', err);
        }
      });
    }
  }

  // Ouvre le dialogue d'upload pour ajouter un nouveau document
  openUploadDialog(): void {
    const dialogRef = this.dialog.open(UploadDocumentDialogComponent, {
      width: '400px',
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.loadDocuments();
      }
    });
  }

  // Méthode pour télécharger un document
  downloadDocument(documentId: number): void {
    this.documentService.downloadDocument(documentId).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `document_${documentId}`; // Nom du fichier à personnaliser si nécessaire
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Erreur lors du téléchargement du document', err);
      }
    });
  }
}
