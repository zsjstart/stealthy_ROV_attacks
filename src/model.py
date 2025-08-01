import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, BatchNorm, global_add_pool, global_mean_pool, global_max_pool
from torch_geometric.data import Data
from stable_baselines3.common.policies import BasePolicy

class GCNModel(nn.Module):
    def __init__(self, 
                 in_channels, 
                 hidden_channels, 
                 out_channels, 
                 layers_pre_mp, 
                 layers_mp, 
                 layers_post_mp, 
                 stage_type, 
                 batchnorm, 
                 act, 
                 dropout, 
                 agg):
        super(GCNModel, self).__init__()

        self.stage_type = stage_type
        self.agg_type = agg
        self.dropout = dropout
        
        # Activation function
        activations = {'relu': nn.ReLU, 'prelu': nn.PReLU, 'swish': nn.SiLU}
        self.activation = activations[act]()
        
        # Pre-MP layers
        self.pre_mp_layers = nn.ModuleList()
        for _ in range(layers_pre_mp):
            self.pre_mp_layers.append(nn.Linear(in_channels if len(self.pre_mp_layers) == 0 else hidden_channels, hidden_channels))
            if batchnorm:
                self.pre_mp_layers.append(BatchNorm(hidden_channels))
            self.pre_mp_layers.append(self.activation)
            self.pre_mp_layers.append(nn.Dropout(dropout))
        
        # MP (Message Passing) layers
        self.mp_layers = nn.ModuleList()
        for _ in range(layers_mp):
            self.mp_layers.append(GCNConv(hidden_channels, hidden_channels))
            if batchnorm:
                self.mp_layers.append(BatchNorm(hidden_channels))
            self.mp_layers.append(self.activation)
            self.mp_layers.append(nn.Dropout(dropout))
        
        # Post-MP layers
        self.post_mp_layers = nn.ModuleList()
        for _ in range(layers_post_mp):
            self.post_mp_layers.append(nn.Linear(hidden_channels, hidden_channels))
            if batchnorm:
                self.post_mp_layers.append(BatchNorm(hidden_channels))
            self.post_mp_layers.append(self.activation)
            self.post_mp_layers.append(nn.Dropout(dropout))
        
        # Final classification layer
        self.final_layer = nn.Linear(hidden_channels, out_channels)
    
    def forward(self, x, edge_index, batch=None):
        # Pre-MP Stage
        for layer in self.pre_mp_layers:
            x = layer(x) if isinstance(layer, nn.Module) else x

        # MP Stage
        if self.stage_type == 'stack':
            for layer in self.mp_layers:
                x = layer(x, edge_index) if isinstance(layer, GCNConv) else x
        elif self.stage_type == 'skipsum':
            skip = x
            for layer in self.mp_layers:
                x = layer(x, edge_index) if isinstance(layer, GCNConv) else x
                x = x + skip if isinstance(layer, GCNConv) else x
        elif self.stage_type == 'skipconcat':
            skip_connections = [x]
            for layer in self.mp_layers:
                x = layer(x, edge_index) if isinstance(layer, GCNConv) else x
                if isinstance(layer, GCNConv):
                    skip_connections.append(x)
            x = torch.cat(skip_connections, dim=-1)

        # Aggregation for graph-level tasks
        if batch is not None:
            if self.agg_type == 'add':
                x = global_add_pool(x, batch)
            elif self.agg_type == 'mean':
                x = global_mean_pool(x, batch)
            elif self.agg_type == 'max':
                x = global_max_pool(x, batch)
        
        # Post-MP Stage
        for layer in self.post_mp_layers:
            x = layer(x) if isinstance(layer, nn.Module) else x

        # Final Layer
        x = self.final_layer(x)
        return F.log_softmax(x, dim=1)

# Model Builder Function
def build_gcn_model(config):
    return GCNModel(
        in_channels=config['in_channels'],
        hidden_channels=config['hidden_channels'],
        out_channels=config['out_channels'],
        layers_pre_mp=config['gnn.layers_pre_mp'],
        layers_mp=config['gnn.layers_mp'],
        layers_post_mp=config['gnn.layers_post_mp'],
        stage_type=config['gnn.stage_type'],
        batchnorm=config['gnn.batchnorm'],
        act=config['gnn.act'],
        dropout=config['gnn.dropout'],
        agg=config['gnn.agg']
    )


class GNNPolicyWrapper(BasePolicy):
    def __init__(self, observation_space, action_space, lr_schedule, gnn_model):
        super(GNNPolicyWrapper, self).__init__(observation_space, action_space)
        self.gnn_model = gnn_model
        self.optimizer = torch.optim.Adam(self.parameters(), lr=lr_schedule(1))

    def forward(self, observations):
        """
        Forward pass through the GNN policy.
        
        Args:
            observations: Graph data object.
        
        Returns:
            Action probabilities or logits.
        """
        logits = self.gnn_model(observations)
        return logits

    def _predict(self, observation, deterministic=False):
        """
        Predict actions given observations.
        """

        logits = self.forward(Data(**observation))
        probs = torch.softmax(logits, dim=-1)
        if deterministic:
            return probs.argmax(dim=-1)
        else:
            return torch.distributions.Categorical(probs).sample()
