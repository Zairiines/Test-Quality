import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TableEntrepriseComponent } from './table-entreprise.component';

describe('TableEntrepriseComponent', () => {
  let component: TableEntrepriseComponent;
  let fixture: ComponentFixture<TableEntrepriseComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TableEntrepriseComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(TableEntrepriseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
