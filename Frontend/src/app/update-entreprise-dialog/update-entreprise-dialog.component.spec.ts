import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UpdateEntrepriseDialogComponent } from './update-entreprise-dialog.component';

describe('UpdateEntrepriseDialogComponent', () => {
  let component: UpdateEntrepriseDialogComponent;
  let fixture: ComponentFixture<UpdateEntrepriseDialogComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UpdateEntrepriseDialogComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(UpdateEntrepriseDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
