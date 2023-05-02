### Instructions for setting up tracing using tempo in Grafana Cloud


#### Setup config map
```kubectl apply -n monitoring -f config-map.yaml```

#### Setup Clusterrole and binding
```kubectl apply -n monitoring -f clusterrole.yaml```

#### Setup service account and token
```kubectl apply -n monitoring -f sa.yaml```

#### Setup deployment and service
```kubectl apply -n monitoring -f deploy.yaml```