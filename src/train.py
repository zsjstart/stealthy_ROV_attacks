import wandb
import torch
import torch.nn.functional as F

from src.model import build_gcn_model


def build_optimizer(config, model):
    pass

def training_closure(train_loader, val_loader):
    def train():
        wandb.init()
        config = wandb.config()

        model = build_gcn_model(config)
        optimizer = build_optimizer(config, model)
        
        # Function to calculate accuracy
        def compute_accuracy(pred, labels):
            pred_labels = pred.argmax(dim=1)
            return (pred_labels == labels).sum().item() / labels.size(0)
        
        # Training loop
        for epoch in range(1, config.epochs + 1):
            model.train()
            train_loss = 0
            train_acc = 0
            
            for batch in train_loader:
                optimizer.zero_grad()
                out = model(batch.x, batch.edge_index)  # Forward pass
                loss = F.cross_entropy(out, batch.y)  # Compute loss
                loss.backward()
                optimizer.step()

                train_loss += loss.item() * batch.num_graphs
                train_acc += compute_accuracy(out, batch.y) * batch.num_graphs
        
            train_loss /= len(train_loader.dataset)
            train_acc /= len(train_loader.dataset)
        
            # Validation loop
            model.eval()
            val_loss = 0
            val_acc = 0
            with torch.no_grad():
                for batch in val_loader:
                    out = model(batch.x, batch.edge_index)
                    loss = F.cross_entropy(out, batch.y)
        
                    val_loss += loss.item() * batch.num_graphs
                    val_acc += compute_accuracy(out, batch.y) * batch.num_graphs
        
            val_loss /= len(val_loader.dataset)
            val_acc /= len(val_loader.dataset)
        
            # Log metrics to wandb
            wandb.log({
                "epoch": epoch,
                "train_loss": train_loss,
                "train_acc": train_acc,
                "val_loss": val_loss,
                "val_acc": val_acc,
            })
        
            print(f"Epoch {epoch:03d} | Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | "
                f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")
        
        # Finish wandb run
        wandb.finish()

    return train