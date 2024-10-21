import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { DocumentService } from '../services/document.service';

@Component({
  selector: 'app-upload-document-dialog',
  templateUrl: './upload-document-dialog.component.html',
  styleUrls: ['./upload-document-dialog.component.scss']
})
export class UploadDocumentDialogComponent {
  selectedFile: File | null = null;
  title: string = '';
  description: string = '';
  type: string = '';
  contractId: number | null = null; // Change to number | null for better validation

  constructor(
    private dialogRef: MatDialogRef<UploadDocumentDialogComponent>,
    private documentService: DocumentService
  ) {}

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0];
  }

  onSubmit() {
    if (this.selectedFile && this.title && this.description && this.type && this.contractId != null) {
      this.documentService.uploadDocument(this.selectedFile, this.title, this.description, this.type, this.contractId)
        .subscribe(
          response => {
            alert('Document uploaded successfully.');
            this.dialogRef.close();
          },
          error => alert('Upload failed: ' + error.message)
        );
    } else {
      alert('Please fill all fields and select a file.');
    }
  }

  onCancel() {
    this.dialogRef.close();
  }
}
