package gateways

import (
	"testing"

	"github.com/hashicorp/consul/agent/consul/state"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/stretchr/testify/require"
)

func TestBindGateways(t *testing.T) {
	type testCase struct {
		gateways                 []*structs.BoundAPIGatewayConfigEntry
		route                    structs.BoundRoute
		expectedBoundAPIGateways []*structs.BoundAPIGatewayConfigEntry
		expectedReferenceErrors  map[structs.ResourceReference]error
		expectedError            error
	}

	cases := map[string]testCase{
		"TCP Route binds to gateway": {
			gateways: []*structs.BoundAPIGatewayConfigEntry{
				{
					Kind: structs.BoundAPIGateway,
					Name: "Test Bound API Gateway",
					Listeners: []structs.BoundAPIGatewayListener{
						{
							Name:   "Test Listener",
							Routes: []structs.ResourceReference{},
						},
					},
				},
			},
			route: &structs.TCPRouteConfigEntry{
				Kind: structs.TCPRoute,
				Name: "Test TCP Route",
				Parents: []structs.ResourceReference{
					{
						Kind:        structs.BoundAPIGateway,
						Name:        "Test Bound API Gateway",
						SectionName: "Test Listener",
					},
				},
			},
			expectedBoundAPIGateways: []*structs.BoundAPIGatewayConfigEntry{
				{
					Kind: structs.BoundAPIGateway,
					Name: "Test Bound API Gateway",
					Listeners: []structs.BoundAPIGatewayListener{
						{
							Name: "Test Listener",
							Routes: []structs.ResourceReference{
								{
									Kind: structs.TCPRoute,
									Name: "Test TCP Route",
								},
							},
						},
					},
				},
			},
			expectedReferenceErrors: map[structs.ResourceReference]error{},
			expectedError:           nil,
		},
		// "TCP Route unbinds from gateway": {
		// 	gateways: []*structs.BoundAPIGatewayConfigEntry{
		// 		{
		// 			Kind: structs.BoundAPIGateway,
		// 			Name: "Test Bound API Gateway",
		// 			Listeners: []structs.BoundAPIGatewayListener{
		// 				{
		// 					Name: "Test Listener",
		// 					Routes: []structs.ResourceReference{
		// 						{
		// 							Kind: structs.TCPRoute,
		// 							Name: "Test TCP Route",
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	route: &structs.TCPRouteConfigEntry{
		// 		Kind: structs.TCPRoute,
		// 		Name: "Test TCP Route",
		// 		Parents: []structs.ResourceReference{
		// 			{
		// 				Kind:        structs.BoundAPIGateway,
		// 				Name:        "Some other test Bound API Gateway",
		// 				SectionName: "Test Listener",
		// 			},
		// 		},
		// 	},
		// 	expectedBoundAPIGateways: []*structs.BoundAPIGatewayConfigEntry{
		// 		{
		// 			Kind: structs.BoundAPIGateway,
		// 			Name: "Test Bound API Gateway",
		// 			Listeners: []structs.BoundAPIGatewayListener{
		// 				{
		// 					Name:   "Test Listener",
		// 					Routes: []structs.ResourceReference{},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	expectedReferenceErrors: map[structs.ResourceReference]error{},
		// 	expectedError:           nil,
		// },
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Create a store for the BoundAPIGateways and put them in it.
			store := state.NewStateStore(nil)
			for i, gateway := range tc.gateways {
				require.NoError(t, store.EnsureConfigEntry(uint64(i), gateway))
			}

			actualBoundAPIGateways, actualReferenceErrors, actualError := BindRouteToGateways(store, tc.route)

			for i, gateway := range tc.expectedBoundAPIGateways {
				require.ElementsMatch(t, gateway.Listeners, actualBoundAPIGateways[i].Listeners)
			}
			require.Equal(t, tc.expectedReferenceErrors, actualReferenceErrors, "ReferenceErrors should match")
			require.Equal(t, tc.expectedError, actualError, "Error should match")
		})
	}
}
