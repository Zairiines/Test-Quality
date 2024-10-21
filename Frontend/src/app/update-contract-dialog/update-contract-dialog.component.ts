import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ContractDTO } from '../models/contract.model';

@Component({
  selector: 'app-update-contract-dialog',
  templateUrl: './update-contract-dialog.component.html',
  styleUrls: ['./update-contract-dialog.component.scss']
})
export class UpdateContractDialogComponent {
  form: FormGroup;

  constructor(
    private fb: FormBuilder,
    public dialogRef: MatDialogRef<UpdateContractDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { contract: ContractDTO }
  ) {
    this.form = this.fb.group({
      title: [data.contract.title, Validators.required],              // Champ "Title"
      description: [data.contract.description, Validators.required],  // Champ "Description"
      entrepriseName: [data.contract.entrepriseName, Validators.required],
      dateDebut: [data.contract.dateDebut, Validators.required],
      dateFin: [data.contract.dateFin, Validators.required]
    });
  }

  onUpdate(): void {
    if (this.form.valid) {
      const updatedContract: ContractDTO = {
        ...this.data.contract,
        ...this.form.value
      };
      this.dialogRef.close(updatedContract);
    }
  }

  onCancel(): void {
    this.dialogRef.close();
  }
}
